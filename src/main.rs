#[macro_use]
extern crate clap;
#[macro_use]
extern crate rocket;

use colored::*;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::figment::providers::{Env, Format, Toml};
use rocket::response::Redirect;
use rocket::{config::TlsConfig, fs::NamedFile};
use rocket_dyn_templates::Template;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

#[get("/<path..>")]
async fn file_server(path: std::path::PathBuf) -> Option<NamedFile> {
    let mut path = Path::new(&std::env::var("ROOT").unwrap_or(".".to_string())).join(path);
    if path.is_dir() {
        path.push("index.html")
    }
    NamedFile::open(path).await.ok()
}

#[derive(rocket::serde::Serialize)]
#[serde(crate = "rocket::serde")]
struct Dir {
    name: String,
    modified: String,
}

#[derive(rocket::serde::Serialize)]
#[serde(crate = "rocket::serde")]
struct File {
    name: String,
    size: u64,
    modified: String,
}

#[derive(rocket::serde::Serialize)]
#[serde(crate = "rocket::serde")]
struct IndexContext<'r> {
    title: &'r str,
    paths: Vec<&'r str>,
    dirs: Vec<Dir>,
    files: Vec<File>,
}

#[derive(Responder)]
enum Resp {
    #[response(status = 200)]
    Index(Template),
    #[response(status = 404)]
    NotFound(&'static str),
    #[response(status = 200)]
    File(Option<NamedFile>),
    #[response(status = 302)]
    Redirect(Redirect),
}

#[catch(404)]
async fn not_found(request: &rocket::Request<'_>) -> Resp {
    let path = request.uri().path();
    let root = std::env::var("ROOT").unwrap_or(".".to_string());
    let root = Path::new(&root);
    let localpath = path.to_string();
    let localpath = localpath[1..localpath.len()].to_string();
    // Remove the / in front of the path, if the path with / is spliced, the previous path will be ignored
    let localpath = &root.join(localpath);
    // Show dotfiles, std::path::PathBuf does not match the url beginning with the dot
    let show_dot_files = std::env::var("DOTFILES").unwrap_or("false".to_string()) == "true";
    if localpath.is_file() && show_dot_files {
        return Resp::File(NamedFile::open(localpath).await.ok());
    }
    // Single-Page Application support
    if root.join("index.html").is_file()
        && std::env::var("SPA").unwrap_or("false".to_string()) == "true"
    {
        return Resp::File(NamedFile::open(&root.join("index.html")).await.ok());
    }
    if !localpath.is_dir() {
        return Resp::NotFound("");
    }
    if !path.ends_with("/") {
        return Resp::Redirect(Redirect::to(path.to_string() + "/"));
    }
    let mut context = IndexContext {
        title: "",
        paths: vec![],
        dirs: vec![],
        files: vec![],
    };
    for path in path.split('/') {
        if path == "" {
            continue;
        }
        context.paths.push(path.as_str());
    }
    match std::fs::read_dir(localpath) {
        Err(e) => println!("{} {}", "Error".bright_red(), e.to_string()),
        Ok(paths) => {
            for path in paths {
                let path = match path {
                    Ok(a) => a,
                    Err(e) => {
                        println!("{} {}", "Error".bright_red(), e.to_string());
                        continue;
                    }
                };
                let filename = match path.file_name().to_str() {
                    Some(str) => str.to_string(),
                    None => {
                        println!("{} {}", "Error".bright_red(), "Read filename error");
                        continue;
                    }
                };
                if !show_dot_files && filename.starts_with(".") {
                    continue;
                }
                let metadata = match path.metadata() {
                    Ok(data) => data,
                    Err(e) => {
                        println!("{} {}", "Error".bright_red(), e.to_string());
                        continue;
                    }
                };
                let modified = match metadata.modified() {
                    Ok(time) => chrono::DateTime::<chrono::Local>::from(time).to_string(),
                    Err(e) => {
                        println!("{} {}", "Error".bright_red(), e.to_string());
                        continue;
                    }
                };
                if metadata.is_dir() {
                    context.dirs.push(Dir {
                        name: filename,
                        modified: modified,
                    })
                } else if metadata.is_file() {
                    context.files.push(File {
                        name: filename,
                        size: metadata.len(),
                        modified: modified,
                    })
                }
            }
        }
    }
    Resp::Index(Template::render("index", &context))
}

struct Logger {}

#[rocket::async_trait]
impl Fairing for Logger {
    fn info(&self) -> Info {
        Info {
            name: "Logger",
            kind: Kind::Liftoff | Kind::Response,
        }
    }
    async fn on_liftoff(&self, rocket: &rocket::Rocket<rocket::Orbit>) {
        println!(
            "{}",
            format!(
                "Serving {} on {}{}:{}",
                std::env::var("ROOT").unwrap_or("[Get Path Error]".to_string()),
                if rocket.config().tls_enabled() {
                    "https://"
                } else {
                    "http://"
                },
                rocket.config().address.to_string(),
                rocket.config().port.to_string()
            )
            .bright_green()
        );
    }
    async fn on_response<'r>(
        &self,
        request: &'r rocket::Request<'_>,
        response: &mut rocket::Response<'r>,
    ) {
        println!(
            "[{}] {} | {} | {} {}",
            chrono::Local::now()
                .format("%Y/%m/%d %H:%M:%S")
                .to_string()
                .bright_blue(),
            request
                .client_ip()
                .unwrap_or(IpAddr::from([0, 0, 0, 0]))
                .to_string()
                .bright_blue(),
            if response.status().code < 400 {
                response.status().code.to_string().bright_green()
            } else {
                response.status().code.to_string().bright_red()
            },
            request.method().to_string().bright_blue(),
            request.uri().to_string().bright_blue()
        );
    }
}

fn display_path(path: &std::path::Path) -> String {
    let root = Path::canonicalize(path).unwrap().display().to_string();
    if root.starts_with("\\\\?\\") {
        root[4..root.len()].to_string()
    } else {
        root.to_string()
    }
}

#[rocket::main]
async fn main() {
    let matches = clap_app!((crate_name!()) =>
        (version: crate_version!())
        (author: crate_authors!())
        (about: crate_description!())
        (@arg index: -i --index "Enable automatic index page generation")
        (@arg upload: -u --upload "Enable file upload")
        (@arg nocache: --nocache "Disable HTTP cache")
        (@arg nocolor: --nocolor "Disable cli colors")
        (@arg cors: --cors "Enable CORS")
        (@arg spa: --spa "Enable Single-Page Application mode (always serve /index.html when the file is not found)")
        (@arg dotfiles: --dotfiles "Show dotfiles")
        (@arg open: -o --open "Open the page in the default browser")
        (@arg ROOT: default_value["."] {
            |path| match std::fs::metadata(path) {
                Ok(meta) => {
                    if meta.is_dir() {
                        Ok(())
                    } else {
                        Err("Parameter is not a directory".to_owned())
                    }
                }
                Err(e) => Err(e.to_string()),
            }
        } "Root directory")
        (@arg address: -a --address +takes_value default_value["127.0.0.1"] {
            |s| match IpAddr::from_str(&s) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        } "IP address to serve on")
        (@arg port: -p --port +takes_value default_value["8000"] {
            |s| match s.parse::<u16>() {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        } "Port to serve on")
        (@arg auth: --auth +takes_value {
            |s| {
                let parts = s.splitn(2, ':').collect::<Vec<&str>>();
                if parts.len() < 2 || parts.len() >= 2 && parts[1].is_empty() {
                    Err("Password not found".to_owned())
                } else if parts[0].is_empty() {
                    Err("Username not found".to_owned())
                } else {
                    Ok(())
                }
            }
        } "HTTP Auth (username:password)")
        (@arg cert: --cert +takes_value {
            |s| match std::fs::metadata(s) {
                Ok(metadata) => {
                    if metadata.is_file() {
                        Ok(())
                    } else {
                        Err("Parameter is not a file".to_owned())
                    }
                }
                Err(e) => Err(e.to_string()),
            }
        } "Path of TLS/SSL public key (certificate)")
        (@arg key: --key +takes_value {
            |s| match std::fs::metadata(s) {
                Ok(metadata) => {
                    if metadata.is_file() {
                        Ok(())
                    } else {
                        Err("Parameter is not a file".to_owned())
                    }
                }
                Err(e) => Err(e.to_string()),
            }
        } "Path of TLS/SSL private key")
    )
    .get_matches();

    std::env::set_var(
        "ROOT",
        display_path(Path::new(matches.value_of("ROOT").unwrap_or("."))),
    );

    std::env::set_var("SPA", matches.is_present("spa").to_string());
    std::env::set_var("DOTFILES", matches.is_present("dotfiles").to_string());

    if matches.is_present("nocolor") {
        colored::control::set_override(false);
    }

    let figment = rocket::Config::figment()
        .merge((
            "address",
            IpAddr::from_str(matches.value_of("address").unwrap_or("127.0.0.1")).unwrap(),
        ))
        .merge((
            "port",
            matches
                .value_of("port")
                .unwrap_or("8000")
                .parse::<u16>()
                .unwrap(),
        ))
        .merge((
            "ident",
            std::env::var("WEB_SERVER_NAME").unwrap_or("timpaik'web server".to_string()),
        ))
        .merge(("cli_colors", matches.is_present("color")))
        .merge(("log_level", "off"))
        .merge(("template_dir", "."))
        // The default is "templates/", an error will be reported if the folder is not found
        .merge(Toml::file(Env::var_or("WEB_CONFIG", "web.toml")).nested())
        .merge(Env::prefixed("WEB_").ignore(&["PROFILE"]).global());

    let enable_tls = matches.is_present("cert") && matches.is_present("key");

    let figment = if enable_tls {
        let cert = Path::new(matches.value_of("cert").unwrap());
        let key = Path::new(matches.value_of("key").unwrap());
        figment.merge(("tls", TlsConfig::from_paths(cert, key)))
    } else {
        figment
    };

    if matches.is_present("open") {
        let url = format!(
            "{}{}:{}",
            if enable_tls {
                "https://".to_string()
            } else {
                "http://".to_string()
            },
            matches
                .value_of("address")
                .unwrap_or("127.0.0.1")
                .to_string(),
            matches.value_of("port").unwrap_or("8000").to_string()
        );
        if cfg!(target_os = "windows") {
            std::process::Command::new("explorer").arg(url).spawn().ok();
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("open").arg(url).spawn().ok();
        } else if cfg!(target_os = "linux") {
            std::process::Command::new("xdg-open").arg(url).spawn().ok();
        }
    }

    match rocket::custom(figment)
        .attach(Logger {})
        .attach(Template::custom(|engines| {
            engines
                .tera
                .add_raw_template("index", include_str!("../templates/index.html.tera"))
                .unwrap();
        }))
        .mount("/", routes![file_server])
        .register("/", catchers![not_found])
        .launch()
        .await
    {
        Ok(_) => {}
        Err(e) => {
            println!("{}", format!("[Error] {}", e.to_string()).bright_red());
        }
    };
}
