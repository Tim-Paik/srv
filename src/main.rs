#[macro_use]
extern crate clap;
#[macro_use]
extern crate rocket;

use colored::*;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{config::TlsConfig, fs::NamedFile};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

#[get("/<path..>")]
async fn index(path: std::path::PathBuf) -> Option<NamedFile> {
    NamedFile::open(path).await.ok()
}

#[catch(404)]
fn not_found() {}

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
                "Serving {} on {}:{}",
                std::env::var("ROOT").unwrap_or("[Get Path Error]".to_string()),
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
        print!(
            "[{}] {} | {} | {} {}",
            chrono::Local::now()
                .format("%Y/%m/%d %H:%M:%S")
                .to_string()
                .white(),
            request
                .client_ip()
                .unwrap_or(IpAddr::from([0, 0, 0, 0]))
                .to_string()
                .white(),
            if response.status().code < 400 {
                response.status().code.to_string().bright_green()
            } else {
                response.status().code.to_string().bright_red()
            },
            request.method().to_string().bright_blue(),
            request.uri().to_string().bright_blue()
        );
        println!("");
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

    std::env::set_var("ROOT", {
        let root = Path::canonicalize(Path::new(matches.value_of("ROOT").unwrap()))
            .unwrap()
            .display()
            .to_string();
        if root.starts_with("\\\\?\\") {
            root[4..root.len()].to_string()
        } else {
            root.to_string()
        }
    });

    if matches.is_present("nocolor") {
        colored::control::set_override(false);
    }

    let figment = rocket::Config::figment()
        .merge((
            "address",
            IpAddr::from_str(matches.value_of("address").unwrap())
                .unwrap_or(IpAddr::from([127, 0, 0, 1])),
        ))
        .merge((
            "port",
            matches
                .value_of("port")
                .unwrap()
                .parse::<u16>()
                .unwrap_or(8000),
        ))
        .merge((
            "ident",
            std::env::var("WEB_SERVER_NAME").unwrap_or("timpaik'server".to_string()),
        ))
        .merge(("cli_colors", matches.is_present("color")))
        .merge(("log_level", "off"));

    let enable_tls = matches.is_present("cert") && matches.is_present("key");

    let figment = if enable_tls {
        let cert = Path::new(matches.value_of("cert").unwrap());
        let key = Path::new(matches.value_of("key").unwrap());
        figment.merge(("tls", TlsConfig::from_paths(cert, key)))
    } else {
        figment
    };

    if matches.is_present("open") {
        let url = if enable_tls {
            "https://".to_string()
        } else {
            "http://".to_string()
        };
        let url = url
            + &matches.value_of("address").unwrap().to_string()
            + ":"
            + &matches.value_of("port").unwrap().to_string();
        if cfg!(target_os = "windows") {
            std::process::Command::new("explorer").arg(url).spawn().ok();
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("open").arg(url).spawn().ok();
        } else if cfg!(target_os = "linux") {
            std::process::Command::new("xdg-open").arg(url).spawn().ok();
        }
    }

    rocket::custom(figment)
        .attach(Logger {})
        .mount("/", routes![index])
        .register("/", catchers![not_found])
        .launch()
        .await
        .unwrap();
}
