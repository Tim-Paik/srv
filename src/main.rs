/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

mod filetype;

use actix_web::{
    dev::{Response, Service, ServiceRequest, ServiceResponse},
    http, middleware, App, HttpRequest, HttpResponse, HttpServer,
};
use actix_web_httpauth::{
    extractors::{basic::BasicAuth, AuthenticationError},
    headers::www_authenticate::basic::Basic,
    middleware::HttpAuthentication,
};
use askama_actix::TemplateToResponse;
use clap::{arg, command, ArgAction};
use env_logger::fmt::Color;
use log::{error, info};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    borrow::Cow,
    env::{set_var, var},
    fs::{self, metadata, read_dir, read_to_string},
    io::{self, BufReader, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
};
use time::OffsetDateTime;

#[derive(Deserialize)]
struct Package {
    name: String,
}

#[derive(Deserialize)]
struct CargoToml {
    package: Package,
}

#[derive(Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct Dir {
    name: String,
    modified: String,
}

#[derive(Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct File {
    name: String,
    size: u64,
    filetype: String,
    modified: String,
}

#[derive(askama_actix::Template)]
#[template(path = "index.html")]
#[derive(Serialize)]
struct IndexContext {
    title: String,
    readme: String,
    paths: Vec<String>,
    dirs: Vec<Dir>,
    files: Vec<File>,
}

fn render_index(
    dir: &actix_files::Directory,
    req: &HttpRequest,
) -> Result<ServiceResponse, io::Error> {
    let mut index = dir.path.clone();
    index.push("index.html");
    if index.exists() && index.is_file() {
        let res = actix_files::NamedFile::open(index)?
            .set_content_type(mime_guess::mime::TEXT_HTML_UTF_8)
            .into_response(req);
        return Ok(ServiceResponse::new(req.to_owned(), res));
    }
    if var("NOINDEX").unwrap_or_else(|_| "false".to_string()) == "true" {
        return Ok(ServiceResponse::new(
            req.to_owned(),
            HttpResponse::NotFound().body(""),
        ));
    }
    let show_dot_files = var("DOTFILES").unwrap_or_else(|_| "false".to_string()) == "true";
    let mut context = IndexContext {
        title: "".to_string(),
        readme: "".to_string(),
        paths: vec![],
        dirs: vec![],
        files: vec![],
    };
    for path in req.path().split('/') {
        if path.is_empty() {
            continue;
        }
        let path = urlencoding::decode(path).unwrap_or(Cow::Borrowed("[Parse URL Error]"));
        let path = path.into_owned();
        context.paths.push(path);
    }
    let mut readme_str = "".to_string();
    match read_dir(&dir.path) {
        Err(e) => {
            error!(target: "read_dir", "[ERROR] Read dir error: {}", e.to_string());
        }
        Ok(paths) => {
            for path in paths {
                let path = match path {
                    Ok(path) => path,
                    Err(e) => {
                        error!(target: "read_dir", "[ERROR] Read path error: {}", e.to_string());
                        continue;
                    }
                };
                let name = match path.file_name().to_str() {
                    Some(str) => str.to_string(),
                    None => {
                        error!(target: "read_dir", "[ERROR] Read filename error");
                        continue;
                    }
                };
                if !show_dot_files && name.starts_with('.') {
                    continue;
                }
                let metadata = match path.metadata() {
                    Ok(data) => data,
                    Err(e) => {
                        error!(target: "read_dir", "[ERROR] Read metadata error: {}", e.to_string());
                        continue;
                    }
                };
                let modified = match metadata.modified() {
                    Ok(time) => OffsetDateTime::from(time)
                        .format(time::macros::format_description!(
                            "[year]/[month]/[day] [hour]:[minute]:[second]"
                        ))
                        .unwrap_or_else(|_| "".to_string()),
                    Err(e) => {
                        error!(target: "read_dir", "[ERROR] Read modified time error: {}", e.to_string());
                        continue;
                    }
                };
                if metadata.is_dir() {
                    context.dirs.push(Dir { name, modified });
                } else if metadata.is_file() {
                    let size = metadata.len();
                    let filetype = filetype::get_file_type(&path.path());
                    context.files.push(File {
                        name,
                        size,
                        filetype,
                        modified,
                    });
                    if path.file_name().to_ascii_lowercase() == "readme.md" {
                        readme_str = read_to_string(path.path()).unwrap_or_else(|_| "".to_string());
                    }
                }
            }
        }
    }
    if var("NOREADME").unwrap_or_else(|_| "false".to_string()) != "true" {
        context.readme = comrak::markdown_to_html(
            &readme_str,
            &comrak::ComrakOptions {
                extension: comrak::ComrakExtensionOptions {
                    strikethrough: true,
                    tagfilter: true,
                    table: true,
                    autolink: true,
                    tasklist: true,
                    superscript: true,
                    header_ids: None,
                    footnotes: true,
                    description_lists: true,
                    front_matter_delimiter: None,
                },
                parse: comrak::ComrakParseOptions {
                    smart: false,
                    default_info_string: None,
                },
                render: comrak::ComrakRenderOptions {
                    hardbreaks: false,
                    github_pre_lang: false,
                    width: 1000,
                    unsafe_: true,
                    escape: false,
                    list_style: comrak::ListStyleType::default(),
                },
            },
        );
    }
    context.title = context.paths.last().unwrap_or(&"/".to_string()).to_string();
    context.dirs.sort();
    context.files.sort();
    Ok(ServiceResponse::new(req.to_owned(), context.to_response()))
}

#[inline]
fn display_path(path: &Path) -> String {
    let root = Path::canonicalize(path).unwrap().display().to_string();
    if root.starts_with("\\\\?\\") {
        root[4..root.len()].to_string()
    } else {
        root
    }
}

#[inline]
fn hash(from: &str) -> String {
    let mut hasher = sha2::Sha512::new();
    hasher.update(from);
    format!("{:?}", hasher.finalize())
}

#[inline]
async fn validator(
    req: ServiceRequest,
    auth: BasicAuth,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    if auth.user_id()
        == var("AUTH_USERNAME")
            .unwrap_or_else(|_| "".to_string())
            .as_str()
        && hash(auth.password().unwrap_or(&Cow::from("")))
            == var("AUTH_PASSWORD")
                .unwrap_or_else(|_| "".to_string())
                .as_str()
    {
        return Ok(req);
    }
    let err = AuthenticationError::new(Basic::with_realm("Incorrect username or password"));
    Err((actix_web::Error::from(err), req))
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let check_does_dir_exits = |path: &str| match metadata(path) {
        Ok(meta) => {
            if meta.is_dir() {
                Ok(path.to_string())
            } else {
                Err("Parameter is not a directory".to_owned())
            }
        }
        Err(e) => Err(e.to_string()),
    };
    let check_does_file_exits = |path: &str| match metadata(path) {
        Ok(metadata) => {
            if metadata.is_file() {
                Ok(path.to_string())
            } else {
                Err("Parameter is not a file".to_owned())
            }
        }
        Err(e) => Err(e.to_string()),
    };
    let check_is_ip_addr = |s: &str| match IpAddr::from_str(s) {
        Ok(_) => Ok(s.to_string()),
        Err(e) => Err(e.to_string()),
    };
    let check_is_port_num = |s: &str| match s.parse::<u16>() {
        Ok(_) => Ok(s.to_string()),
        Err(e) => Err(e.to_string()),
    };
    let check_is_auth = |s: &str| {
        let parts = s.splitn(2, ':').collect::<Vec<&str>>();
        if parts.len() < 2 || parts.len() >= 2 && parts[1].is_empty() {
            Err("Password not found".to_owned())
        } else if parts[0].is_empty() {
            Err("Username not found".to_owned())
        } else {
            Ok(s.to_string())
        }
    };
    let matches = command!()
        .arg(arg!(--noindex "Disable automatic index page generation").required(false))
        .arg(arg!(--noreadme "Disable automatic readme rendering").required(false))
        .arg(arg!(--nocache "Disable HTTP cache").required(false))
        .arg(arg!(--nocolor "Disable cli colors").required(false))
        .arg(arg!(--cors [hostname] "Enable CORS [with custom value]").required(false).action(ArgAction::Append))
        .arg(arg!(--spa "Enable Single-Page Application mode (always serve /index.html when the file is not found)").required(false))
        .arg(arg!(-d --dotfiles "Show dotfiles").required(false))
        .arg(arg!(-o --open "Open the page in the default browser").required(false))
        .arg(arg!(-q --quiet "Disable access log output").required(false))
        .arg(arg!(--quietall "Disable all output").required(false))
        .arg(arg!([root] "Root directory").default_value(".").value_parser(check_does_dir_exits))
        .arg(arg!(-a --address <ipaddr> "IP address to serve on").default_value("0.0.0.0").value_parser(check_is_ip_addr))
        .arg(arg!(-p --port <port> "Port to serve on").default_value("8000").value_parser(check_is_port_num))
        .arg(arg!(--auth <pattern> "HTTP Auth (username:password)").required(false).value_parser(check_is_auth))
        .arg(arg!(--cert <path> "Path of TLS/SSL public key (certificate)").required(false).value_parser(check_does_file_exits))
        .arg(arg!(--key <path> "Path of TLS/SSL private key").required(false).value_parser(check_does_file_exits))
        .subcommand(clap::Command::new("doc")
            .about("Open cargo doc via local server (Need cargo installation)")
            .arg(arg!(--nocolor "Disable cli colors"))
            .arg(arg!(--noopen "Do not open the page in the default browser"))
            .arg(arg!(--log "Enable access log output [default: disabled]"))
            .arg(arg!(--quietall "Disable all output"))
            .arg(arg!(-a --address <ipaddr> "IP address to serve on").required(false).default_value("0.0.0.0").value_parser(check_is_ip_addr))
            .arg(arg!(-p --port <port> "Port to serve on").required(false).default_value("8000").value_parser(check_is_port_num))
        )
        .get_matches();

    set_var(
        "ROOT",
        display_path(Path::new(
            matches
                .get_one::<String>("root")
                .unwrap_or(&".".to_string()),
        )),
    );

    set_var("NOINDEX", matches.get_flag("noindex").to_string());
    set_var("NOREADME", matches.get_flag("noreadme").to_string());
    set_var("SPA", matches.get_flag("spa").to_string());
    set_var("DOTFILES", matches.get_flag("dotfiles").to_string());
    set_var("NOCACHE", matches.get_flag("nocache").to_string());

    if matches.get_flag("quiet") {
        set_var("RUST_LOG", "info,actix_web::middleware::logger=off");
    }
    if matches.get_flag("quietall") {
        set_var("RUST_LOG", "off");
    }
    if matches.get_flag("nocolor") {
        set_var("RUST_LOG_STYLE", "never");
    }

    if let Some(s) = matches.get_one::<String>("auth") {
        set_var("ENABLE_AUTH", matches.get_flag("auth").to_string());
        let parts = s.splitn(2, ':').collect::<Vec<&str>>();
        set_var("AUTH_USERNAME", parts[0]);
        set_var("AUTH_PASSWORD", hash(parts[1]));
    }

    if let Some(mut cors) = matches.get_many::<String>("cors") {
        set_var("ENABLE_CORS", "true");
        match cors.next() {
            Some(value) => set_var("CORS", value),
            None => set_var("CORS", "*"),
        }
    }

    let enable_tls =
        matches.get_one::<String>("cert").is_some() && matches.get_one::<String>("key").is_some();
    let ip = matches
        .get_one::<String>("address")
        .unwrap_or(&"127.0.0.1".to_string())
        .to_string();
    let addr = format!(
        "{}:{}",
        ip,
        matches
            .get_one::<String>("port")
            .unwrap_or(&"8000".to_string())
    );
    let url = format!(
        "{}{}:{}",
        if enable_tls {
            "https://".to_string()
        } else {
            "http://".to_string()
        },
        if ip == "0.0.0.0" { "127.0.0.1" } else { &ip },
        matches
            .get_one::<String>("port")
            .unwrap_or(&"8000".to_string())
    );

    let open_in_browser = |url: &str| {
        if cfg!(target_os = "windows") {
            Command::new("explorer").arg(url).spawn().ok();
        } else if cfg!(target_os = "macos") {
            Command::new("open").arg(url).spawn().ok();
        } else if cfg!(target_os = "linux")
            || cfg!(target_os = "android")
            || cfg!(target_os = "freebsd")
            || cfg!(target_os = "dragonfly")
            || cfg!(target_os = "openbsd")
            || cfg!(target_os = "netbsd")
        {
            Command::new("xdg-open").arg(url).spawn().ok();
        }
    };

    if matches.get_flag("open") {
        open_in_browser(&url);
    }

    if let Some(matches) = matches.subcommand_matches("doc") {
        if !matches.get_flag("log") {
            set_var("RUST_LOG", "info,actix_web::middleware::logger=off");
        }
        if matches.get_flag("quietall") {
            set_var("RUST_LOG", "off");
        }
        if matches.get_flag("nocolor") {
            set_var("RUST_LOG_STYLE", "never");
        }
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(move |buf, record| {
            let data = record.args().to_string();
            let mut style = buf.style();
            let blue = style.set_color(Color::Cyan);
            let mut style = buf.style();
            let red = style.set_color(Color::Red);
            let mut style = buf.style();
            let green = style.set_color(Color::Green);
            if record.target() == "actix_web::middleware::logger" {
                let data: Vec<&str> = data.splitn(5, '^').collect();
                let time = blue.value(
                    OffsetDateTime::parse(data[0], &time::format_description::well_known::Rfc3339)
                        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
                        .format(time::macros::format_description!(
                            "[year]/[month]/[day] [hour]:[minute]:[second]"
                        ))
                        .unwrap_or_else(|_| "".to_string()),
                );
                let ipaddr = blue.value(data[1]);
                let status_code = data[2].parse().unwrap_or(500);
                let status_code = if status_code < 400 {
                    green.value(status_code)
                } else {
                    red.value(status_code)
                };
                let process_time: Vec<&str> = data[3].splitn(2, '.').collect();
                let process_time = process_time[0].to_string() + "ms";
                let process_time = blue.value(if process_time.len() == 3 {
                    "  ".to_string() + &process_time
                } else if process_time.len() == 4 {
                    " ".to_string() + &process_time
                } else {
                    process_time
                });
                let content = blue.value(
                    urlencoding::decode(data[4])
                        .unwrap_or(Cow::Borrowed("[Parse URL Error]"))
                        .into_owned(),
                );
                return writeln!(
                    buf,
                    "[{}] {} | {} | {} | {}",
                    time, ipaddr, status_code, process_time, content
                );
            } else if record.target() == "actix_server::builder" {
                if data.starts_with("Starting ") && data.ends_with(" workers") {
                    return Ok(());
                }
            } else if record.target() == "actix_server::server" {
                if data == "Actix runtime found; starting in Actix runtime" {
                    let data = format!(
                        "[INFO] Serving {} on {}",
                        var("ROOT").unwrap_or_else(|_| ".".to_string()),
                        var("LISTEN_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8000".to_string())
                    );
                    return writeln!(buf, "\r{}", green.value(data));
                }
                if data == "SIGINT received; starting forced shutdown" {
                    return writeln!(
                        buf,
                        "\r{}",
                        green.value("[INFO] SIGINT received; starting forced shutdown")
                    );
                    // Add '\r' to remove the input ^C
                }
                return Ok(());
            } else if record.target() == "actix_server::worker"
                || record.target() == "actix_server::accept"
            {
                return Ok(());
            }
            if data.starts_with("[ERROR]")
                || data.starts_with("TLS alert")
                || data.starts_with("Failed")
            {
                writeln!(buf, "\r{}", red.value(data))
            } else {
                writeln!(buf, "\r{}", green.value(data))
            }
        })
        .init();

    let addr = if let Some(matches) = matches.subcommand_matches("doc") {
        let mut cargo_toml = match fs::File::open("./Cargo.toml") {
            Ok(file) => file,
            Err(e) => {
                error!("[ERROR] {}", e.to_string());
                return Ok(());
            }
        };
        let mut contents = String::new();
        match cargo_toml.read_to_string(&mut contents) {
            Ok(_) => {}
            Err(e) => {
                error!("[ERROR] {}", e.to_string());
                return Ok(());
            }
        }
        let contents: CargoToml = match toml::from_str(&contents) {
            Ok(t) => t,
            Err(e) => {
                error!("[ERROR] {}", e.to_string());
                return Ok(());
            }
        };
        let crate_name = contents.package.name;
        info!("[INFO] Generating document (may take a while)");
        match Command::new("cargo")
            .arg("doc")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
        {
            Ok(status) => {
                if !status.success() {
                    match status.code() {
                        Some(code) => error!("[ERROR] Cargo exited with status code: {code}"),
                        None => error!("[ERROR] Cargo terminated by signal"),
                    }
                    return Ok(());
                }
            }
            Err(e) => {
                error!("[ERROR] Cargo Error: {}", e.to_string());
                return Ok(());
            }
        }
        let path = Path::new("./target/doc/");
        let mut index_path = path.to_path_buf();
        index_path.push(crate_name.to_string() + "/index.html");
        if !index_path.exists() || !index_path.is_file() {
            error!("[ERROR] Cargo Error: doc path not found");
            return Ok(());
        }
        set_var("ROOT", display_path(path));
        let ip = matches
            .get_one::<String>("address")
            .unwrap_or(&"127.0.0.1".to_string())
            .to_string();
        let addr = format!(
            "{}:{}",
            ip,
            matches
                .get_one::<String>("port")
                .unwrap_or(&"8000".to_string())
        );
        let url = format!(
            "http://{}:{}/{}/index.html",
            if ip == "0.0.0.0" { "127.0.0.1" } else { &ip },
            matches
                .get_one::<String>("port")
                .unwrap_or(&"8000".to_string()),
            crate_name,
        );
        if !matches.get_flag("noopen") {
            open_in_browser(&url);
        }
        addr
    } else {
        addr
    };
    set_var("LISTEN_ADDRESS", addr);

    let server = HttpServer::new(move || {
        let app = App::new()
            .wrap_fn(|req, srv| {
                let paths = PathBuf::from_str(req.path()).unwrap_or_default();
                let mut isdotfile = false;
                for path in paths.iter() {
                    if path.to_string_lossy().starts_with('.') {
                        isdotfile = true;
                    }
                }
                let fut = srv.call(req);
                async move {
                    Ok(fut.await?.map_body(|head, body| {
                        if var("NOCACHE").unwrap_or_else(|_| "false".to_string()) == "true" {
                            head.headers_mut().insert(
                                http::header::CACHE_CONTROL,
                                http::header::HeaderValue::from_static("no-store"),
                            );
                        }
                        if var("ENABLE_CORS").unwrap_or_else(|_| "false".to_string()) == "true" {
                            let cors = var("CORS").unwrap_or_else(|_| "*".to_string());
                            let cors = http::header::HeaderValue::from_str(&cors)
                                .unwrap_or_else(|_| http::header::HeaderValue::from_static("*"));
                            head.headers_mut()
                                .insert(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, cors);
                        }
                        if isdotfile
                            && var("DOTFILES").unwrap_or_else(|_| "false".to_string()) != "true"
                        {
                            return Response::new(http::StatusCode::FORBIDDEN).into_body();
                        }
                        body
                    }))
                }
            })
            .wrap(middleware::Compress::default())
            .wrap(middleware::Condition::new(
                var("ENABLE_AUTH").unwrap_or_else(|_| "false".to_string()) == "true",
                HttpAuthentication::basic(validator),
            ))
            .wrap(middleware::Logger::new("%t^%a^%s^%D^%r"));
        let files = actix_files::Files::new("/", var("ROOT").unwrap_or_else(|_| ".".to_string()))
            .use_hidden_files()
            .prefer_utf8(true)
            .show_files_listing()
            .files_listing_renderer(render_index)
            .default_handler(|req: ServiceRequest| {
                let (http_req, _payload) = req.into_parts();
                async {
                    let path = var("ROOT").unwrap_or_else(|_| ".".to_string());
                    let mut path = Path::new(&path).to_path_buf();
                    path.push("index.html");
                    if path.exists()
                        && path.is_file()
                        && var("SPA").unwrap_or_else(|_| "false".to_string()) == "true"
                    {
                        let res = actix_files::NamedFile::open(path)?.into_response(&http_req);
                        return Ok(ServiceResponse::new(http_req, res));
                    }
                    Ok(ServiceResponse::new(
                        http_req,
                        HttpResponse::NotFound().body(""),
                    ))
                }
            });
        app.service(files)
    });
    let server = if enable_tls {
        let cert = &mut BufReader::new(
            fs::File::open(Path::new(matches.get_one::<String>("cert").unwrap())).unwrap(),
        );
        let key = &mut BufReader::new(
            fs::File::open(Path::new(matches.get_one::<String>("key").unwrap())).unwrap(),
        );
        let cert = rustls_pemfile::certs(cert)
            .unwrap()
            .iter()
            .map(|x| rustls::Certificate(x.to_vec()))
            .collect::<Vec<_>>();
        let key = rustls::PrivateKey(
            rustls_pemfile::pkcs8_private_keys(key)
                .unwrap()
                .first()
                .expect("no private key found")
                .to_owned(),
        );
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .expect("bad certificate/key");
        server.bind_rustls(
            var("LISTEN_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8000".to_string()),
            config,
        )
    } else {
        server.bind(var("LISTEN_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8000".to_string()))
    };
    server?.run().await
}
