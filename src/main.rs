#[macro_use] extern crate clap;
#[macro_use] extern crate rocket;

use rocket::fs::NamedFile;
use std::str::FromStr;

#[get("/<path..>")]
async fn index(path: std::path::PathBuf) -> Option<NamedFile> {
    NamedFile::open(path).await.ok()
}

#[rocket::main]
async fn main() {
    let _matches = clap_app!((crate_name!()) =>
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
        (@arg listen: -l --listen +takes_value default_value["127.0.0.1"] {
            |s| match std::net::IpAddr::from_str(&s) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        } "IP address to bind")
        (@arg port: -p --port +takes_value default_value["8080"] {
            |s| match s.parse::<u16>() {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        } "Port number")
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
    rocket::build()
        .mount("/", routes![index])
        .launch()
        .await
        .unwrap();
}
