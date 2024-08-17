use clap::{arg, value_parser};
use packets::{is_http, is_tls_hello, part_tls};
use socket2::SockRef;
use socks5_server::{
    auth::NoAuth,
    connection::state::NeedAuthenticate,
    proto::{Address, Error, Reply},
    Command, IncomingConnection, Server,
};
use std::{io::Error as IoError, sync::Arc};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
mod packets;

// used template https://github.com/EAimTY/socks5-server/blob/master/socks5-server/examples/simple_socks5.rs
#[tokio::main]
async fn main() -> Result<(), IoError> {
    let matches = clap::Command::new("rust-dpi")
        .version("0.1")
        .arg(arg!(--ip <VALUE>).default_value("0.0.0.0"))
        .arg(arg!(--port <VALUE>).default_value("1080"))
        .arg(arg!(--disorder <VALUE>).value_parser(value_parser!(usize)))
        .arg(arg!(--split <VALUE>).value_parser(value_parser!(usize)))
        .arg(arg!(--oob <VALUE>).value_parser(value_parser!(usize)))
        .arg(arg!(--tlsrec <VALUE>).value_parser(value_parser!(usize)))
        .get_matches();
    
    let ip = matches.get_one::<String>("ip").expect("need ip");
    let port = matches.get_one::<String>("port").expect("need port");
    let tlsrec = matches.get_one::<usize>("tlsrec").map(|pos| Part { pos: pos.clone(), flag: None });

    let disorder = matches.get_one::<usize>("disorder")
        .map(|pos| Method::Disorder(Part { pos: pos.clone(), flag: None }));
    let split = matches.get_one::<usize>("split")
        .map(|pos| Method::Split(Part { pos: pos.clone(), flag: None }));
    let oob = matches.get_one::<usize>("oob")
        .map(|pos| Method::Oob(Part { pos: pos.clone(), flag: None }));

    let listener = TcpListener::bind(format!("{ip}:{port}")).await?;
    let auth = Arc::new(NoAuth) as Arc<_>;

    let server = Server::new(listener, auth);
    
    let mut methods: Vec<Method> = vec![disorder, split, oob].into_iter().flatten().collect();
    methods.sort_by(|a, b|method_part(b).pos.cmp(&method_part(a).pos));
    
    let params = Params {
        tlsrec: tlsrec,
        methods: methods
    };

    while let Ok((conn, _)) = server.accept().await {
        let params = params.clone();
        tokio::spawn(async move {
            match handle(conn, params).await {
                Ok(()) => {}
                Err(err) => eprintln!("{err}"),
            }
        });
    }

    Ok(())
}

async fn handle(conn: IncomingConnection<(), NeedAuthenticate>, params: Params) -> Result<(), Error> {
    let conn = match conn.authenticate().await {
        Ok((conn, _)) => conn,
        Err((err, mut conn)) => {
            let _ = conn.shutdown().await;
            return Err(err);
        }
    };

    match conn.wait().await {
        Ok(Command::Associate(associate, _)) => {
            let replied = associate
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await;

            let mut conn = match replied {
                Ok(conn) => conn,
                Err((err, mut conn)) => {
                    let _ = conn.shutdown().await;
                    return Err(Error::Io(err));
                }
            };

            let _ = conn.close().await;
        }
        Ok(Command::Bind(bind, _)) => {
            let replied = bind
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await;

            let mut conn = match replied {
                Ok(conn) => conn,
                Err((err, mut conn)) => {
                    let _ = conn.shutdown().await;
                    return Err(Error::Io(err));
                }
            };

            let _ = conn.close().await;
        }
        Ok(Command::Connect(connect, addr)) => {
            let target = match addr {
                Address::DomainAddress(domain, port) => {
                    let domain = String::from_utf8_lossy(&domain);
                    TcpStream::connect((domain.as_ref(), port)).await
                }
                Address::SocketAddress(addr) => TcpStream::connect(addr).await,
            };
            
            if let Ok(mut target) = target {
                let replied = connect
                    .reply(Reply::Succeeded, Address::unspecified())
                    .await;

                let mut conn = match replied {
                    Ok(conn) => conn,
                    Err((err, mut conn)) => {
                        let _ = conn.shutdown().await;
                        return Err(Error::Io(err));
                    }
                };
                
                let conn = conn.get_mut();
                let nodelay = target.nodelay()?;

                target.set_nodelay(true)?;
                desync_hello_phrase(conn, &mut target, params).await?;
                target.set_nodelay(nodelay)?;

                copy_bidirectional(conn, &mut target).await?;
            } else {
                let replied = connect
                    .reply(Reply::HostUnreachable, Address::unspecified())
                    .await;

                let mut conn = match replied {
                    Ok(conn) => conn,
                    Err((err, mut conn)) => {
                        let _ = conn.shutdown().await;
                        return Err(Error::Io(err));
                    }
                };

                let _ = conn.shutdown().await;
            }
        }
        Err((err, mut conn)) => {
            let _ = conn.shutdown().await;
            return Err(err);
        }
    }

    Ok(())
}

async fn desync_hello_phrase<'a, R>(
    reader: &'a mut R,
    writer: &'a mut TcpStream,
    params: Params
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized
{
    let mut hello_buf = [0; 9016];
    let n = reader.read(&mut hello_buf).await?;
    let buffer = &hello_buf[..n];
    let is_https = is_tls_hello(buffer).is_some();
    if is_https | is_http(buffer).is_some()  {
        desync(buffer,
            params,
            writer,
            is_https).await?;
    }
    else {
        writer.write(buffer).await?;
    } 
    writer.flush().await
}

async fn desync<'a>(bytes: &[u8], params: Params, tcp_stream: &mut TcpStream, is_https: bool) -> Result<(), Error> {
    let mut buffer = Vec::with_capacity(bytes.len());
    bytes.clone_into(&mut buffer);

    if let Some(part) = &params.tlsrec {
        if is_https && part.pos < buffer.len() {
            part_tls(&mut buffer, part.pos);
        }
    }

    let mut offset = 0;
    for method in &params.methods {
        let pos = method_part(&method).pos;
        if pos <= offset || pos >= buffer.len() {
            break;
        }
        match method {
            Method::Split(part) => {
                tcp_stream.write_all(&buffer[offset..part.pos]).await?;
                tcp_stream.flush().await?;
            }
            Method::Disorder(part) => {
                let ttl = tcp_stream.ttl()?;
                tcp_stream.set_ttl(1)?;
                tcp_stream.write_all(&buffer[offset..part.pos]).await?;
                tcp_stream.flush().await?;
                tcp_stream.set_ttl(ttl)?;
            }
            Method::Oob(part) => {
                let sock = SockRef::from(&tcp_stream);
                let ch = buffer[part.pos];
                buffer[part.pos] = b'a';
                sock.send_out_of_band(&buffer[offset..part.pos + 1])?;
                buffer[part.pos] = ch;
            }
        }
        offset = pos;
    }
    if offset < buffer.len() {
        tcp_stream.write_all(&buffer[offset..]).await?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct Params {
    tlsrec: Option<Part>,
    methods: Vec<Method>
}

#[derive(Clone, Debug)]
enum Flag {
    OffsetSni,
    OffsetHost
}

#[derive(Clone, Debug)]
enum Method {
    Split(Part),
    Disorder(Part),
    Oob(Part)
}

fn method_part(m: &Method) -> &Part {
    match m {
        Method::Split(p)
        | Method::Disorder(p)
        | Method::Oob(p)
        => p
    }
}

#[derive(Clone, Debug)]
struct Part {
    pos: usize,
    flag: Option<Flag>
}
