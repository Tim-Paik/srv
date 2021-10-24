/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;

use actix_files as fs;
use actix_web::{
    dev::{self, Service, ServiceResponse},
    http, middleware, App, HttpResponse, HttpServer,
};
use clap::Arg;
use env_logger::fmt::Color;
use log::{error, info};
use sha2::Digest;
use std::{
    env::{set_var, var},
    fs::read_dir,
    io::{BufReader, Error, ErrorKind, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

lazy_static! {
    pub static ref TEMPLATE: tera::Tera = {
        let mut tera = tera::Tera::default();
        tera.add_raw_template("index", include_str!("../templates/index.html.tera"))
            .unwrap();
        tera
    };
}

#[inline]
fn get_file_type(from: &Path) -> String {
    match from.extension() {
        Some(os_str) => match os_str.to_str().unwrap_or("") {
            "7z" => "archive",
            "bz" => "archive",
            "bz2" => "archive",
            "cab" => "archive",
            "gz" => "archive",
            "iso" => "archive",
            "rar" => "archive",
            "xz" => "archive",
            "zip" => "archive",
            "zst" => "archive",
            "zstd" => "archive",
            "doc" => "word",
            "docx" => "word",
            "ppt" => "powerpoint",
            "pptx" => "powerpoint",
            "xls" => "excel",
            "xlsx" => "excel",
            "heic" => "image",
            "pdf" => "pdf",
            // JavaScript / TypeScript
            "js" => "code",
            "cjs" => "code",
            "mjs" => "code",
            "jsx" => "code",
            "ts" => "code",
            "tsx" => "code",
            "json" => "code",
            "coffee" => "code",
            // HTML / CSS
            "html" => "code",
            "htm" => "code",
            "xml" => "code",
            "xhtml" => "code",
            "vue" => "code",
            "ejs" => "code",
            "template" => "code",
            "tmpl" => "code",
            "pug" => "code",
            "art" => "code",
            "hbs" => "code",
            "tera" => "code",
            "css" => "code",
            "scss" => "code",
            "sass" => "code",
            "less" => "code",
            // Python
            "py" => "code",
            "pyc" => "code",
            // JVM
            "java" => "code",
            "kt" => "code",
            "kts" => "code",
            "gradle" => "code",
            "groovy" => "code",
            "scala" => "code",
            "jsp" => "code",
            // Shell
            "sh" => "code",
            // Php
            "php" => "code",
            // C / C++
            "c" => "code",
            "cc" => "code",
            "cpp" => "code",
            "h" => "code",
            "cmake" => "code",
            // C#
            "cs" => "code",
            "xaml" => "code",
            "sln" => "code",
            "csproj" => "code",
            // Golang
            "go" => "code",
            "mod" => "code",
            "sum" => "code",
            // Swift
            "swift" => "code",
            "plist" => "code",
            "xib" => "code",
            "xcconfig" => "code",
            "entitlements" => "code",
            "xcworkspacedata" => "code",
            "pbxproj" => "code",
            // Ruby
            "rb" => "code",
            // Rust
            "rs" => "code",
            // Objective-C
            "m" => "code",
            // Dart
            "dart" => "code",
            // Microsoft
            "manifest" => "code",
            "rc" => "code",
            "cmd" => "code",
            "bat" => "code",
            "ps1" => "code",
            // Config
            "ini" => "code",
            "yaml" => "code",
            "toml" => "code",
            "conf" => "code",
            "properties" => "code",
            "lock" => "alt",
            _ => match mime_guess::from_path(from).first_or_octet_stream().type_() {
                mime_guess::mime::AUDIO => "audio",
                mime_guess::mime::IMAGE => "image",
                mime_guess::mime::PDF => "pdf",
                mime_guess::mime::VIDEO => "video",
                mime_guess::mime::TEXT => "alt",
                _ => "file",
            },
        },
        None => "file",
    }
    .to_string()
}

#[derive(serde::Deserialize)]
struct Package {
    name: String,
}

#[derive(serde::Deserialize)]
struct CargoToml {
    package: Package,
}

#[derive(Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
struct Dir {
    name: String,
    modified: String,
}

#[derive(Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
struct File {
    name: String,
    size: u64,
    filetype: String,
    modified: String,
}

#[derive(serde::Serialize)]
struct IndexContext {
    title: String,
    paths: Vec<String>,
    dirs: Vec<Dir>,
    files: Vec<File>,
}

fn render_index(
    dir: &actix_files::Directory,
    req: &actix_web::HttpRequest,
) -> Result<ServiceResponse, std::io::Error> {
    let mut index = dir.path.clone();
    index.push("index.html");
    if index.exists() && index.is_file() {
        let res = match actix_files::NamedFile::open(index)?
            .set_content_type(mime_guess::mime::TEXT_HTML_UTF_8)
            .into_response(req)
        {
            Ok(res) => res,
            Err(e) => return Err(Error::new(ErrorKind::Other, e.to_string())),
        };
        return Ok(ServiceResponse::new(req.clone(), res));
    }
    if var("NOINDEX").unwrap_or_else(|_| "false".to_string()) == "true" {
        return Ok(ServiceResponse::new(
            req.clone(),
            HttpResponse::NotFound().body(""),
        ));
    }
    let show_dot_files = var("DOTFILES").unwrap_or_else(|_| "false".to_string()) == "true";
    let mut context = IndexContext {
        title: "".to_string(),
        paths: vec![],
        dirs: vec![],
        files: vec![],
    };
    for path in req.path().split('/') {
        if path.is_empty() {
            continue;
        }
        let path =
            urlencoding::decode(path).unwrap_or(std::borrow::Cow::Borrowed("[Parse URL Error]"));
        let path = path.into_owned();
        context.paths.push(path);
    }
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
                    Ok(time) => chrono::DateTime::<chrono::Local>::from(time)
                        .format("%Y/%m/%d %H:%M:%S")
                        .to_string(),
                    Err(e) => {
                        error!(target: "read_dir", "[ERROR] Read modified time error: {}", e.to_string());
                        continue;
                    }
                };
                if metadata.is_dir() {
                    context.dirs.push(Dir { name, modified });
                } else if metadata.is_file() {
                    let size = metadata.len();
                    let filetype = get_file_type(&path.path());
                    context.files.push(File {
                        name,
                        size,
                        filetype,
                        modified,
                    });
                }
            }
        }
    }
    context.title = context.paths.last().unwrap_or(&"/".to_string()).to_string();
    context.dirs.sort();
    context.files.sort();
    let content = tera::Context::from_serialize(&context);
    let content = match content {
        Ok(ctx) => ctx,
        Err(e) => {
            error!(target: "tera::Context::from_serialize", "[ERROR] Read modified time error: {}", e.to_string());
            return Err(Error::new(ErrorKind::Other, e.to_string()));
        }
    };
    let index = TEMPLATE
        .render("index", &content)
        .unwrap_or_else(|_| "TEMPLATE RENDER ERROR".to_string());
    let res = HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(index);
    Ok(ServiceResponse::new(req.clone(), res))
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
    req: dev::ServiceRequest,
    auth: actix_web_httpauth::extractors::basic::BasicAuth,
) -> Result<dev::ServiceRequest, actix_web::Error> {
    if auth.user_id()
        == var("AUTH_USERNAME")
            .unwrap_or_else(|_| "".to_string())
            .as_str()
        && hash(auth.password().unwrap_or(&std::borrow::Cow::from("")))
            == var("AUTH_PASSWORD")
                .unwrap_or_else(|_| "".to_string())
                .as_str()
    {
        return Ok(req);
    }
    let err = actix_web_httpauth::extractors::AuthenticationError::new(
        actix_web_httpauth::headers::www_authenticate::basic::Basic::with_realm(
            "Incorrect username or password",
        ),
    );
    Err(actix_web::Error::from(err))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let check_does_dir_exits = |path: &str| match std::fs::metadata(path) {
        Ok(meta) => {
            if meta.is_dir() {
                Ok(())
            } else {
                Err("Parameter is not a directory".to_owned())
            }
        }
        Err(e) => Err(e.to_string()),
    };
    let check_does_file_exits = |path: &str| match std::fs::metadata(path) {
        Ok(metadata) => {
            if metadata.is_file() {
                Ok(())
            } else {
                Err("Parameter is not a file".to_owned())
            }
        }
        Err(e) => Err(e.to_string()),
    };
    let check_is_ip_addr = |s: &str| match IpAddr::from_str(s) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    };
    let check_is_port_num = |s: &str| match s.parse::<u16>() {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    };
    let check_is_auth = |s: &str| {
        let parts = s.splitn(2, ':').collect::<Vec<&str>>();
        if parts.len() < 2 || parts.len() >= 2 && parts[1].is_empty() {
            Err("Password not found".to_owned())
        } else if parts[0].is_empty() {
            Err("Username not found".to_owned())
        } else {
            Ok(())
        }
    };
    let matches = clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::new("noindex").long("noindex").about("Disable automatic index page generation"))
        .arg(Arg::new("compress").short('c').long("compress").about("Enable streaming compression (Content-length/segment download will be disabled)"))
        .arg(Arg::new("nocache").long("nocache").about("Disable HTTP cache"))
        .arg(Arg::new("nocolor").long("nocolor").about("Disable cli colors"))
        .arg(Arg::new("cors").long("cors").takes_value(true).min_values(0).max_values(1).about("Enable CORS [with custom value]"))
        .arg(Arg::new("spa").long("spa").about("Enable Single-Page Application mode (always serve /index.html when the file is not found)"))
        .arg(Arg::new("dotfiles").short('d').long("dotfiles").about("Show dotfiles"))
        .arg(Arg::new("open").short('o').long("open").about("Open the page in the default browser"))
        .arg(Arg::new("quiet").short('q').long("quiet").about("Disable access log output"))
        .arg(Arg::new("quietall").long("quietall").about("Disable all output"))
        .arg(Arg::new("ROOT").default_value(".").validator(check_does_dir_exits).about("Root directory"))
        .arg(Arg::new("address").short('a').long("address").default_value("0.0.0.0").takes_value(true).validator(check_is_ip_addr).about("IP address to serve on"))
        .arg(Arg::new("port").short('p').long("port").default_value("8000").takes_value(true).validator(check_is_port_num).about("Port to serve on"))
        .arg(Arg::new("auth").long("auth").takes_value(true).validator(check_is_auth).about("HTTP Auth (username:password)"))
        .arg(Arg::new("cert").long("cert").takes_value(true).validator(check_does_file_exits).about("Path of TLS/SSL public key (certificate)"))
        .arg(Arg::new("key").long("key").takes_value(true).validator(check_does_file_exits).about("Path of TLS/SSL private key"))
        .subcommand(clap::App::new("doc")
            .about("Open cargo doc via local server (Need cargo installation)")
            .arg(Arg::new("nocolor").long("nocolor").about("Disable cli colors"))
            .arg(Arg::new("noopen").long("noopen").about("Do not open the page in the default browser"))
            .arg(Arg::new("log").long("log").about("Enable access log output [default: disabled]"))
            .arg(Arg::new("quietall").long("quietall").about("Disable all output"))
            .arg(Arg::new("address").short('a').long("address").default_value("0.0.0.0").takes_value(true).validator(check_is_ip_addr).about("IP address to serve on"))
            .arg(Arg::new("port").short('p').long("port").default_value("8000").takes_value(true).validator(check_is_port_num).about("Port to serve on"))
        )
        .get_matches();

    set_var(
        "ROOT",
        display_path(Path::new(matches.value_of("ROOT").unwrap_or("."))),
    );

    set_var("NOINDEX", matches.is_present("noindex").to_string());
    set_var("SPA", matches.is_present("spa").to_string());
    set_var("DOTFILES", matches.is_present("dotfiles").to_string());
    set_var("NOCACHE", matches.is_present("nocache").to_string());
    set_var("COMPRESS", matches.is_present("compress").to_string());

    if matches.is_present("quiet") {
        set_var("RUST_LOG", "info,actix_web::middleware::logger=off");
    }
    if matches.is_present("quietall") {
        set_var("RUST_LOG", "off");
    }
    if matches.is_present("nocolor") {
        set_var("RUST_LOG_STYLE", "never");
    }

    if let Some(s) = matches.value_of("auth") {
        set_var("ENABLE_AUTH", matches.is_present("auth").to_string());
        let parts = s.splitn(2, ':').collect::<Vec<&str>>();
        set_var("AUTH_USERNAME", parts[0]);
        set_var("AUTH_PASSWORD", hash(parts[1]));
    }

    if matches.is_present("cors") {
        set_var("ENABLE_CORS", matches.is_present("cors").to_string());
        match matches.value_of("cors") {
            Some(str) => {
                set_var("CORS", str.to_string());
            }
            None => {
                set_var("CORS", "*");
            }
        }
    }

    let enable_tls = matches.is_present("cert") && matches.is_present("key");
    let ip = matches
        .value_of("address")
        .unwrap_or("127.0.0.1")
        .to_string();
    let addr = format!(
        "{}:{}",
        ip,
        matches.value_of("port").unwrap_or("8000").to_string()
    );
    let url = format!(
        "{}{}:{}",
        if enable_tls {
            "https://".to_string()
        } else {
            "http://".to_string()
        },
        if ip == "0.0.0.0" { "127.0.0.1" } else { &ip },
        matches.value_of("port").unwrap_or("8000").to_string()
    );

    let open_in_browser = |url: &str| {
        if cfg!(target_os = "windows") {
            std::process::Command::new("explorer").arg(url).spawn().ok();
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("open").arg(url).spawn().ok();
        } else if cfg!(target_os = "linux")
            || cfg!(target_os = "android")
            || cfg!(target_os = "freebsd")
            || cfg!(target_os = "dragonfly")
            || cfg!(target_os = "openbsd")
            || cfg!(target_os = "netbsd")
        {
            std::process::Command::new("xdg-open").arg(url).spawn().ok();
        }
    };

    if matches.is_present("open") {
        open_in_browser(&url);
    }

    let addr = if let Some(matches) = matches.subcommand_matches("doc") {
        let mut cargo_toml = match std::fs::File::open("./Cargo.toml") {
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
        match std::process::Command::new("cargo").arg("doc").output() {
            Ok(output) => {
                let output = std::str::from_utf8(&output.stderr).unwrap_or("");
                if output.starts_with("error: could not find `Cargo.toml` in") {
                    error!("[ERROR] Cargo.toml Not Found");
                    return Ok(());
                } else if output.starts_with("error: ") {
                    error!(
                        "[ERROR] {}",
                        output.strip_prefix("error: ").unwrap_or(output)
                    );
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
            .value_of("address")
            .unwrap_or("127.0.0.1")
            .to_string();
        let addr = format!(
            "{}:{}",
            ip,
            matches.value_of("port").unwrap_or("8000").to_string()
        );
        let url = format!(
            "http://{}:{}/{}/index.html",
            if ip == "0.0.0.0" { "127.0.0.1" } else { &ip },
            matches.value_of("port").unwrap_or("8000").to_string(),
            crate_name,
        );
        if !matches.is_present("noopen") {
            open_in_browser(&url);
        }
        if !matches.is_present("log") {
            set_var("RUST_LOG", "info,actix_web::middleware::logger=off");
        }
        if matches.is_present("quietall") {
            set_var("RUST_LOG", "off");
        }
        if matches.is_present("nocolor") {
            set_var("RUST_LOG_STYLE", "never");
        }
        addr
    } else {
        addr
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
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
                    chrono::NaiveDateTime::from_str(data[0])
                        .unwrap()
                        .format("%Y/%m/%d %H:%M:%S")
                        .to_string(),
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
                        .unwrap_or(std::borrow::Cow::Borrowed("[Parse URL Error]"))
                        .into_owned(),
                );
                return writeln!(
                    buf,
                    "[{}] {} | {} | {} | {}",
                    time, ipaddr, status_code, process_time, content
                );
            } else if record.target() == "actix_server::builder" {
                if data.starts_with("SIGINT received, exiting") {
                    return writeln!(buf, "\r{}", green.value("[INFO] SIGINT received, exiting"));
                    // Add '\r' to remove the input ^C
                } else {
                    let data = data.replace("actix-web-service-", "");
                    let re1 = regex::Regex::new("Starting (.*) workers").unwrap();
                    if re1.is_match(&data) {
                        return Ok(());
                    }
                    let re2 = regex::Regex::new("Starting \"(.*)\" service on (.*)").unwrap();
                    if re2.is_match(&data) {
                        let addr = re2
                            .captures(&data)
                            .unwrap()
                            .get(1)
                            .map_or("", |m| m.as_str());
                        let data = format!(
                            "[INFO] Serving {} on {}",
                            var("ROOT").unwrap_or_else(|_| ".".to_string()),
                            addr
                        );
                        return writeln!(buf, "\r{}", green.value(data));
                    }
                }
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

    let server = HttpServer::new(move || {
        let compress = if var("COMPRESS").unwrap_or_else(|_| "false".to_string()) == "true" {
            http::header::ContentEncoding::Auto
        } else {
            http::header::ContentEncoding::Identity
        };
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
                                http::HeaderValue::from_static("no-store"),
                            );
                        }
                        if var("ENABLE_CORS").unwrap_or_else(|_| "false".to_string()) == "true" {
                            let cors = var("CORS").unwrap_or_else(|_| "*".to_string());
                            let cors = http::HeaderValue::from_str(&cors)
                                .unwrap_or_else(|_| http::HeaderValue::from_static("*"));
                            head.headers_mut()
                                .insert(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, cors);
                        }
                        if isdotfile
                            && var("DOTFILES").unwrap_or_else(|_| "false".to_string()) != "true"
                        {
                            head.status = http::StatusCode::FORBIDDEN;
                            *head.headers_mut() = http::HeaderMap::new();
                            return dev::ResponseBody::Other(actix_web::body::Body::None);
                        }
                        body
                    }))
                }
            })
            .wrap(middleware::Compress::new(compress))
            .wrap(middleware::Condition::new(
                var("ENABLE_AUTH").unwrap_or_else(|_| "false".to_string()) == "true",
                actix_web_httpauth::middleware::HttpAuthentication::basic(validator),
            ))
            .wrap(middleware::Logger::new("%t^%a^%s^%D^%r"));
        let files = fs::Files::new("/", var("ROOT").unwrap_or_else(|_| ".".to_string()))
            .use_hidden_files()
            .prefer_utf8(true)
            .show_files_listing()
            .files_listing_renderer(render_index)
            .default_handler(|req: dev::ServiceRequest| {
                let (http_req, _payload) = req.into_parts();
                async {
                    let path = var("ROOT").unwrap_or_else(|_| ".".to_string());
                    let mut path = Path::new(&path).to_path_buf();
                    path.push("index.html");
                    if path.exists()
                        && path.is_file()
                        && var("SPA").unwrap_or_else(|_| "false".to_string()) == "true"
                    {
                        let res = fs::NamedFile::open(path)?.into_response(&http_req)?;
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
            std::fs::File::open(Path::new(matches.value_of("cert").unwrap())).unwrap(),
        );
        let key = &mut BufReader::new(
            std::fs::File::open(Path::new(matches.value_of("key").unwrap())).unwrap(),
        );
        let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        let cert_chain = rustls::internal::pemfile::certs(cert).unwrap();
        let mut keys = rustls::internal::pemfile::pkcs8_private_keys(key).unwrap();
        config.set_single_cert(cert_chain, keys.remove(0)).unwrap();
        server.bind_rustls(addr, config)
    } else {
        server.bind(addr)
    };
    server?.run().await
}
