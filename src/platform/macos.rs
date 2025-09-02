use crate::pixel_conversion::convert_sample_buffer_to_rgba;
use crate::platform::traits::{
    DisplayResolution, PixelConverter, ScreenCapture, ScreenCaptureFactory,
};
use screencapturekit::{
    output::CMSampleBuffer,
    shareable_content::SCShareableContent,
    stream::{
        SCStream, configuration::SCStreamConfiguration, configuration::pixel_format::PixelFormat,
        content_filter::SCContentFilter, output_trait::SCStreamOutputTrait,
        output_type::SCStreamOutputType,
    },
};
use std::sync::{Arc, Mutex};

/// macOS implementation using ScreenCaptureKit
pub struct MacOSScreenCapture {
    latest_frame: Arc<Mutex<Option<Vec<u8>>>>,
    stream: Option<SCStream>,
    display_resolution: Option<DisplayResolution>,
}

impl MacOSScreenCapture {
    pub fn new() -> Self {
        Self {
            latest_frame: Arc::new(Mutex::new(None)),
            stream: None,
            display_resolution: None,
        }
    }
}

impl ScreenCapture for MacOSScreenCapture {
    fn get_display_resolution(&self) -> Result<DisplayResolution, String> {
        let shareable = SCShareableContent::get()
            .map_err(|e| format!("Failed to get SCShareableContent: {:?}", e))?;

        let displays = shareable.displays();
        let display = displays.first().ok_or("No displays found")?;

        let width = display.width();
        let height = display.height();

        Ok(DisplayResolution { width, height })
    }

    fn start_capture(
        &mut self,
        exclude_window: Option<&winit::window::Window>,
    ) -> Result<(), String> {
        // Get shareable content + pick the main display
        let shareable = SCShareableContent::get()
            .map_err(|e| format!("Failed to get SCShareableContent: {:?}", e))?;

        let display = shareable
            .displays()
            .first()
            .ok_or("No displays found")?
            .clone();

        // Get actual display resolution
        let resolution = DisplayResolution {
            width: display.width(),
            height: display.height(),
        };
        self.display_resolution = Some(resolution);

        println!(
            "Capturing display at {}x{}",
            resolution.width, resolution.height
        );

        // Build a content filter for the display, excluding our app window if provided
        let mut excluded_windows = Vec::new();

        if exclude_window.is_some()
            && std::env::var("CLOAK_SHARE_ENV").unwrap_or("development".to_string())
                == "development"
        {
            // Find our window in the shareable content by title (only in development)
            for sc_window in shareable.windows() {
                if sc_window.title().contains("CloakShare") {
                    println!("Excluding window: {}", sc_window.title());
                    excluded_windows.push(sc_window);
                }
            }
        }

        let excluded_refs: Vec<&_> = excluded_windows.iter().collect();
        let filter =
            SCContentFilter::new().with_display_excluding_windows(&display, &excluded_refs);

        // Configure the stream with actual display resolution
        let config = SCStreamConfiguration::new()
            .set_width(resolution.width)
            .map_err(|e| format!("Failed to set width: {:?}", e))?
            .set_height(resolution.height)
            .map_err(|e| format!("Failed to set height: {:?}", e))?
            .set_captures_audio(false)
            .map_err(|e| format!("Failed to set audio: {:?}", e))?
            .set_shows_cursor(false)
            .map_err(|e| format!("Failed to hide cursor: {:?}", e))?
            .set_pixel_format(PixelFormat::BGRA)
            .map_err(|e| format!("Failed to set pixel format: {:?}", e))?;

        // Create output handler
        let output_handler = MacOSScreenCaptureOutputHandler {
            frame_data: self.latest_frame.clone(),
            converter: MacOSPixelConverter,
        };

        // Create stream, add output, start
        let mut stream = SCStream::new(&filter, &config);
        stream.add_output_handler(output_handler, SCStreamOutputType::Screen);
        stream
            .start_capture()
            .map_err(|e| format!("Failed to start capture: {:?}", e))?;

        self.stream = Some(stream);
        println!("Screen capture started!");
        Ok(())
    }

    fn get_latest_frame(&self) -> Option<Vec<u8>> {
        self.latest_frame.lock().ok()?.clone()
    }

    fn stop_capture(&mut self) {
        if let Some(stream) = self.stream.take() {
            if let Err(e) = stream.stop_capture() {
                eprintln!("Failed to stop capture: {:?}", e);
            }
        }
    }

    fn get_frame_buffer(&self) -> Arc<Mutex<Option<Vec<u8>>>> {
        self.latest_frame.clone()
    }
}

impl Drop for MacOSScreenCapture {
    fn drop(&mut self) {
        self.stop_capture();
    }
}

/// macOS factory for creating screen capture instances
pub struct MacOSScreenCaptureFactory;

impl ScreenCaptureFactory for MacOSScreenCaptureFactory {
    type Capture = MacOSScreenCapture;

    fn create() -> Self::Capture {
        MacOSScreenCapture::new()
    }
}

/// macOS pixel converter using Core Video
pub struct MacOSPixelConverter;

impl PixelConverter for MacOSPixelConverter {
    fn convert_to_rgba(&self, buffer: &dyn std::any::Any) -> Option<Vec<u8>> {
        // Try to downcast to CMSampleBuffer
        if let Some(sample_buffer) = buffer.downcast_ref::<CMSampleBuffer>() {
            convert_sample_buffer_to_rgba(sample_buffer)
        } else {
            None
        }
    }
}

/// Output handler for ScreenCaptureKit frames on macOS
struct MacOSScreenCaptureOutputHandler {
    frame_data: Arc<Mutex<Option<Vec<u8>>>>,
    converter: MacOSPixelConverter,
}

impl SCStreamOutputTrait for MacOSScreenCaptureOutputHandler {
    fn did_output_sample_buffer(
        &self,
        sample_buffer: CMSampleBuffer,
        output_type: SCStreamOutputType,
    ) {
        if matches!(output_type, SCStreamOutputType::Screen) {
            if let Some(rgba_data) = self.converter.convert_to_rgba(&sample_buffer) {
                if let Ok(mut latest) = self.frame_data.lock() {
                    *latest = Some(rgba_data);
                }
            }
        }
    }
}

/// Platform-specific screen capture manager type alias
pub type PlatformScreenCapture = MacOSScreenCapture;
