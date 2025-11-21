/// Enable conventional "{container-name}:{tag}"
///
pub fn parse_image_name(image_ref: &str) -> (String, String) {
    let (image, tag) = image_ref.split_once(':').unwrap_or((image_ref, "latest"));

    let image_name = if image.contains('/') {
        image.to_string()
    } else {
        format!("library/{}", image)
    };

    (image_name.to_owned(), tag.to_owned())
}

/// ':' is invalid folder name to overlayfs;
/// This way application uses '-' instead of ':'.
///
pub fn normalize_container_id<S: AsRef<str>>(s: S) -> String {
    s.as_ref().replace(':', "-")
}
