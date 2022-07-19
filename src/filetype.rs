#[inline]
pub fn get_file_type(from: &std::path::Path) -> String {
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
