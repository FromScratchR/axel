pub fn parse_image_name(image_ref: &str) -> (String, String) {
    let (image, tag) = image_ref.split_once(':').unwrap_or((image_ref, "latest"));
    let image_name = if image.contains('/') {
        image.to_string()
    } else {
        format!("library/{}", image)
    };

    (image_name.to_owned(), tag.to_owned())
}
