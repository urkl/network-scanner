# 📸 Screenshots Instructions

To create the screenshots for this project, follow these steps:

## Required Screenshots

### 1. Main Dashboard (`main-dashboard.png`)
- **URL**: http://localhost:5000
- **Size**: 1920x1080 or similar
- **Content**: Show the main interface with:
  - Header with Urosk.NET branding
  - Statistics cards showing device counts
  - Search functionality
  - View toggle buttons (Table/Cards)
  - Several devices visible

### 2. Device Cards View (`cards-view.png`) 
- **URL**: http://localhost:5000 (switch to Cards view)
- **Size**: 1920x1080 or similar
- **Content**: Show cards layout with:
  - Multiple device cards visible
  - Different device types with icons (🍎📱🖨️🌐💻)
  - Device information (hostname, IP, vendor, OS)
  - Open ports with clickable badges
  - Rescan buttons visible

### 3. Table View (`table-view.png`)
- **URL**: http://localhost:5000 (switch to Table view)
- **Size**: 1920x1080 or similar  
- **Content**: Show table with:
  - All columns visible (Status, IP, Hostname, MAC, Vendor, OS, Ports, Actions)
  - Multiple devices with different statuses
  - Port badges (some green/clickable, some blue)
  - Action buttons in the Actions column

### 4. Real-time Scanning (`scanning-process.png`)
- **URL**: http://localhost:5000
- **Size**: 1920x1080 or similar
- **Action**: Click rescan button on a device
- **Content**: Show:
  - "🔄 Skeniranje..." badge visible on a device
  - Console showing scan logs (open browser dev tools)
  - Real-time activity demonstration

## Screenshot Tips

1. **Browser Setup**:
   - Use Chrome/Firefox in full-screen
   - Disable bookmarks bar for clean look
   - Set zoom to 100% or 90% for optimal view

2. **Content Preparation**:
   - Ensure you have multiple devices discovered
   - Wait for detailed scanning to complete for realistic data
   - Have diverse device types for better showcase

3. **Quality**:
   - Use high resolution (1920x1080 minimum)
   - Save as PNG format for best quality
   - Ensure good contrast and readability

## Screenshot Commands

If you have screenshot tools available:

```bash
# Linux with gnome-screenshot
gnome-screenshot -w -f screenshots/main-dashboard.png

# macOS
screencapture -w screenshots/main-dashboard.png

# Manual browser screenshot
# Right-click → Inspect → Console → Run:
# window.scrollTo(0,0); setTimeout(() => {}, 500);
```

## File Naming Convention

- `main-dashboard.png` - Main interface overview
- `cards-view.png` - Device cards layout  
- `table-view.png` - Table view with all columns
- `scanning-process.png` - Live scanning demonstration

## Image Requirements

- **Format**: PNG (preferred) or JPG
- **Resolution**: Minimum 1920x1080
- **File size**: Under 2MB each for GitHub
- **Quality**: High clarity, readable text

---

*These screenshots will be used in the main README.md to showcase the Network Scanner's capabilities.*