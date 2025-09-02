mod cross_platform_capture;
mod gpu_renderer;
mod pixel_conversion;
mod platform;
mod safe_mirror;
mod screen_capture;
mod sensitive_data_detector;

use crate::safe_mirror::SafeMirror;
use std::sync::Arc;
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, EventLoop},
    window::{Window, WindowId},
};

/// App: Main application structure using winit's ApplicationHandler pattern
/// This handles window lifecycle events (creation, resize, close, etc.)
struct App {
    /// The GPU renderer (None until window is created)
    safe_mirror: Option<SafeMirror>,
    /// The window handle (None until created)
    window: Option<Arc<Window>>,
    /// Screen capture (created early for resolution detection)
    screen_capture: Option<crate::cross_platform_capture::CrossPlatformScreenCapture>,
}

impl ApplicationHandler for App {
    /// Called when the app starts up or resumes
    /// This is where we create our window and initialize GPU rendering
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        // Create screen capture first for resolution detection
        let mut screen_capture = crate::cross_platform_capture::CrossPlatformScreenCapture::new()
            .expect("Failed to create screen capture");

        // Get display resolution for window sizing
        let resolution = screen_capture.get_display_resolution().unwrap_or_else(|e| {
            eprintln!("Failed to get display resolution: {}, using fallback", e);
            crate::platform::DisplayResolution {
                width: 1280,
                height: 720,
            }
        });

        // Create the main window sized to match display resolution
        let window = Arc::new(
            event_loop
                .create_window(
                    Window::default_attributes()
                        .with_title("CloakShare - Safe Mirror") // Window title
                        .with_inner_size(winit::dpi::LogicalSize::new(
                            resolution.width,
                            resolution.height,
                        )),
                ) // Size to match display
                .unwrap(),
        );

        // Store references and initialize GPU rendering
        self.window = Some(window.clone());
        self.screen_capture = Some(screen_capture);

        // pollster::block_on converts async function to sync (required for this context)
        self.safe_mirror = Some(pollster::block_on(SafeMirror::new(
            window,
            self.screen_capture.take().unwrap(),
        )));
    }

    /// Handles all window events (resize, close, redraw, etc.)
    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        if let Some(safe_mirror) = &mut self.safe_mirror {
            match event {
                // User clicked X button or pressed Cmd+Q
                WindowEvent::CloseRequested => event_loop.exit(),

                // User resized the window
                WindowEvent::Resized(physical_size) => {
                    safe_mirror.resize(physical_size);
                }

                // System requests a redraw (60fps or when window needs updating)
                WindowEvent::RedrawRequested => {
                    // Render the frame to the screen
                    match safe_mirror.update_and_render() {
                        Ok(_) => {} // Successful render

                        // Handle common GPU errors gracefully
                        Err(wgpu::SurfaceError::Lost) => {
                            // GPU lost surface, try to recreate it
                            safe_mirror.resize(safe_mirror.size())
                        }
                        Err(wgpu::SurfaceError::OutOfMemory) => {
                            // GPU out of memory, exit app
                            event_loop.exit()
                        }
                        Err(e) => eprintln!("Render error: {e:?}"),
                    }
                }
                _ => {} // Ignore other events
            }
        }

        // Request continuous redraws for smooth animation
        // This creates our 60fps render loop
        if let Some(window) = &self.window {
            window.request_redraw();
        }
    }
}

/// Main function: Entry point of the application
fn main() {
    println!("Starting CloakShare Safe Mirror...");

    // Create the main event loop (handles window events, user input, etc.)
    let event_loop = EventLoop::new().unwrap();

    // Create our app instance
    let mut app = App {
        safe_mirror: None,    // Will be initialized when window is created
        window: None,         // Will be created in resumed()
        screen_capture: None, // Will be created in resumed()
    };

    // Start the event loop - this runs until the app closes
    // The event loop continuously calls our window_event handler
    event_loop.run_app(&mut app).unwrap();
}
