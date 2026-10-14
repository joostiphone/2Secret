//! Profile photos: whatever image people pick becomes a small square JPEG
//! (a few KB), which is what the account keeps and syncs, encrypted
//! (`Session::set_avatar`).

use base64::Engine;
use image::imageops::FilterType;
use image::ImageReader;

/// Width and height of a profile photo in pixels (sharp at 64 points on
/// high-resolution screens).
pub const SIZE: u32 = 128;

/// The photo as a `data:image/jpeg` URL: cropped to the centre square,
/// scaled to [`SIZE`]. `Err` when the file is not an image this can read.
pub fn prepare(bytes: &[u8]) -> Result<String, String> {
    let image = ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| e.to_string())?
        .decode()
        .map_err(|e| e.to_string())?;
    let side = image.width().min(image.height());
    if side == 0 {
        return Err("empty image".into());
    }
    let square = image.crop_imm((image.width() - side) / 2, (image.height() - side) / 2, side, side);
    let small = square.resize_exact(SIZE, SIZE, FilterType::Lanczos3).to_rgb8();
    let mut jpeg = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 85)
        .encode_image(&small)
        .map_err(|e| e.to_string())?;
    Ok(format!("data:image/jpeg;base64,{}", base64::engine::general_purpose::STANDARD.encode(jpeg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makes_a_small_square_jpeg() {
        let wide = image::RgbImage::from_fn(300, 200, |x, _| image::Rgb([(x % 256) as u8, 80, 160]));
        let mut png = Vec::new();
        image::DynamicImage::ImageRgb8(wide)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        let url = prepare(&png).unwrap();
        assert!(url.starts_with("data:image/jpeg;base64,"));
        assert!(url.len() < twosecret_core::session::MAX_AVATAR_BYTES);
        let jpeg = base64::engine::general_purpose::STANDARD.decode(&url["data:image/jpeg;base64,".len()..]).unwrap();
        let back = image::load_from_memory(&jpeg).unwrap();
        assert_eq!((back.width(), back.height()), (SIZE, SIZE));
        assert!(prepare(b"not an image").is_err());
    }
}
