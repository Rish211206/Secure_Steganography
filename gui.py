"""
gui.py
======
Graphical User Interface (GUI) for "Secure Image Steganography with AES Encryption".
Built with Python's standard Tkinter, ttk, and Pillow (PIL).

Educational Highlights & Features:
1. Dual-Tab Design: Clear separation between "Encode (Hide & Encrypt)" and
   "Decode (Extract & Decrypt)" workflows.
2. Live Capacity Meter: Real-time calculation showing bytes required vs. maximum
   available carrier image capacity as the user types.
3. Live Image Previews: Thumbnail rendering with aspect ratio preservation for
   both carrier and encoded images.
4. Input Validation & Error Handling:
   - Validates missing inputs and password confirmation.
   - Catches CapacityExceededError with friendly suggestions.
   - Catches SteganographyError (e.g. image has no hidden payload).
   - Catches DecryptionError (wrong password or corrupted image).
5. Educational Help Dialog: Integrated explanation of PBKDF2, AES-256-GCM, and
   LSB Steganography.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk

# Import local cryptographic and steganographic modules
from crypto_utils import CryptoError, DecryptionError
from stego_utils import (
    get_image_capacity,
    format_bytes,
    estimate_payload_size,
    encode_message_into_image,
    decode_message_from_image,
    SteganographyError,
    CapacityExceededError,
)


# Styling Palette Constants (Modern Clean Theme)
COLOR_BG = "#F8FAFC"          # Slate 50
COLOR_CARD_BG = "#FFFFFF"     # Pure White
COLOR_BORDER = "#E2E8F0"      # Slate 200
COLOR_TEXT_PRIMARY = "#0F172A"# Slate 900
COLOR_TEXT_MUTED = "#64748B"  # Slate 500
COLOR_PRIMARY = "#2563EB"     # Royal Blue 600
COLOR_PRIMARY_HOVER = "#1D4ED8"
COLOR_SUCCESS = "#16A34A"     # Emerald 600
COLOR_DANGER = "#DC2626"      # Red 600
COLOR_WARNING = "#D97706"     # Amber 600


class SteganographyApp(tk.Tk):
    """Main Application Window for Secure Image Steganography."""

    def __init__(self):
        super().__init__()
        self.title("Secure Image Steganography with AES-256 Encryption")
        self.geometry("980x780")
        self.minsize(860, 680)
        self.configure(bg=COLOR_BG)

        # High-DPI awareness on Windows (improves crispness of text & buttons)
        self._enable_windows_dpi_awareness()

        # State Variables: Encode Tab
        self.encode_carrier_path = None
        self.encode_carrier_image = None
        self.encode_preview_photo = None

        # State Variables: Decode Tab
        self.decode_carrier_path = None
        self.decode_carrier_image = None
        self.decode_preview_photo = None

        # Build UI
        self._configure_styles()
        self._create_menu()
        self._create_header()
        self._create_notebook()
        self._create_status_bar()

    def _enable_windows_dpi_awareness(self):
        """Enables high-DPI scaling on Windows systems gracefully."""
        if sys.platform.startswith("win"):
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                try:
                    import ctypes
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass

    def _configure_styles(self):
        """Configures ttk widget styles for a modern desktop look."""
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Global font preferences
        default_font = ("Segoe UI", 10)
        heading_font = ("Segoe UI", 11, "bold")
        title_font = ("Segoe UI", 14, "bold")

        self.option_add("*Font", default_font)

        # Notebook tabs
        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            font=heading_font,
            padding=[20, 10],
            background=COLOR_BORDER,
            foreground=COLOR_TEXT_PRIMARY,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLOR_PRIMARY)],
            foreground=[("selected", "#FFFFFF")],
        )

        # Buttons
        style.configure(
            "Primary.TButton",
            font=heading_font,
            background=COLOR_PRIMARY,
            foreground="#FFFFFF",
            padding=[16, 8],
            borderwidth=0,
        )
        style.map(
            "Primary.TButton",
            background=[("active", COLOR_PRIMARY_HOVER), ("disabled", COLOR_BORDER)],
            foreground=[("disabled", COLOR_TEXT_MUTED)],
        )

        style.configure(
            "Secondary.TButton",
            font=default_font,
            background=COLOR_CARD_BG,
            foreground=COLOR_TEXT_PRIMARY,
            padding=[12, 6],
        )

        # Progress bar
        style.configure(
            "Capacity.Horizontal.TProgressbar",
            troughcolor=COLOR_BORDER,
            background=COLOR_PRIMARY,
            thickness=14,
        )

    def _create_menu(self):
        """Creates top menu bar with Help, About, and How It Works."""
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="How It Works (Guide)", command=self._show_how_it_works)
        help_menu.add_separator()
        help_menu.add_command(label="About This App", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _create_header(self):
        """Header banner at the top of the application window."""
        header_frame = tk.Frame(self, bg=COLOR_CARD_BG, padx=20, pady=14, relief="ridge", bd=1)
        header_frame.pack(fill="x", padx=16, pady=(12, 8))

        title_lbl = tk.Label(
            header_frame,
            text="Secure Image Steganography",
            font=("Segoe UI", 16, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        title_lbl.pack(anchor="w")

        subtitle_lbl = tk.Label(
            header_frame,
            text="AES-256-GCM Authenticated Encryption with PBKDF2-HMAC-SHA256 & LSB Image Steganography",
            font=("Segoe UI", 9),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
        )
        subtitle_lbl.pack(anchor="w", pady=(2, 0))

    def _create_notebook(self):
        """Creates the primary tabbed interface with Encode and Decode tabs."""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=4)

        # Tab 1: Encode
        self.encode_tab = tk.Frame(self.notebook, bg=COLOR_BG)
        self.notebook.add(self.encode_tab, text="  🔒  Encode (Hide & Encrypt)  ")
        self._build_encode_tab(self.encode_tab)

        # Tab 2: Decode
        self.decode_tab = tk.Frame(self.notebook, bg=COLOR_BG)
        self.notebook.add(self.decode_tab, text="  🔓  Decode (Extract & Decrypt)  ")
        self._build_decode_tab(self.decode_tab)

    def _create_status_bar(self):
        """Status bar at the bottom for quick user guidance and feedback."""
        self.status_var = tk.StringVar(value="Ready. Select an image to begin.")
        status_frame = tk.Frame(self, bg=COLOR_CARD_BG, relief="groove", bd=1, padx=12, pady=4)
        status_frame.pack(fill="x", side="bottom")

        status_lbl = tk.Label(
            status_frame,
            textvariable=self.status_var,
            font=("Segoe UI", 9),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
        )
        status_lbl.pack(side="left")

    # =========================================================================
    # ENCODE TAB IMPLEMENTATION
    # =========================================================================
    def _build_encode_tab(self, parent):
        """Builds all controls, inputs, previews, and meters for the Encode tab."""
        # Scrollable canvas or paned container
        container = tk.Frame(parent, bg=COLOR_BG)
        container.pack(fill="both", expand=True, padx=8, pady=8)

        # Top section: Image Selection & Preview (Grid 2 columns)
        top_frame = tk.Frame(container, bg=COLOR_CARD_BG, padx=16, pady=12, relief="solid", bd=1)
        top_frame.pack(fill="x", pady=(0, 8))

        # Left: Image Selection & Specs
        info_col = tk.Frame(top_frame, bg=COLOR_CARD_BG)
        info_col.pack(side="left", fill="both", expand=True)

        step1_lbl = tk.Label(
            info_col,
            text="Step 1: Select Carrier Image (PNG or JPG)",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        step1_lbl.pack(anchor="w")

        btn_row = tk.Frame(info_col, bg=COLOR_CARD_BG)
        btn_row.pack(anchor="w", pady=(8, 6))

        browse_btn = ttk.Button(
            btn_row,
            text="📁 Browse Carrier Image...",
            style="Secondary.TButton",
            command=self._browse_encode_image,
        )
        browse_btn.pack(side="left")

        self.encode_path_var = tk.StringVar(value="No carrier image selected")
        path_lbl = tk.Label(
            info_col,
            textvariable=self.encode_path_var,
            font=("Segoe UI", 9, "italic"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            wraplength=480,
            justify="left",
        )
        path_lbl.pack(anchor="w", pady=(2, 6))

        # Metrics display
        self.encode_metrics_var = tk.StringVar(
            value="Image Dimensions: — | Max Capacity: —"
        )
        metrics_lbl = tk.Label(
            info_col,
            textvariable=self.encode_metrics_var,
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_PRIMARY,
        )
        metrics_lbl.pack(anchor="w")

        # Right: Image Preview Box
        preview_col = tk.Frame(top_frame, bg=COLOR_CARD_BG, padx=8)
        preview_col.pack(side="right")

        self.encode_preview_lbl = tk.Label(
            preview_col,
            text="[ Image Preview ]\nSelect an image to view",
            bg="#F1F5F9",
            fg=COLOR_TEXT_MUTED,
            width=22,
            height=7,
            relief="groove",
            bd=1,
        )
        self.encode_preview_lbl.pack()

        # Middle Section: Secret Message & Live Capacity Meter
        msg_frame = tk.Frame(container, bg=COLOR_CARD_BG, padx=16, pady=12, relief="solid", bd=1)
        msg_frame.pack(fill="both", expand=True, pady=(0, 8))

        step2_lbl = tk.Label(
            msg_frame,
            text="Step 2: Enter Secret Message",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        step2_lbl.pack(anchor="w")

        self.encode_text = ScrolledText(
            msg_frame,
            height=6,
            font=("Consolas", 10),
            wrap="word",
            relief="solid",
            bd=1,
        )
        self.encode_text.pack(fill="both", expand=True, pady=(6, 6))
        self.encode_text.bind("<KeyRelease>", self._on_encode_text_changed)

        # Capacity Indicator Bar & Label
        meter_row = tk.Frame(msg_frame, bg=COLOR_CARD_BG)
        meter_row.pack(fill="x", pady=(2, 2))

        self.encode_capacity_var = tk.StringVar(
            value="Payload: 0 bytes | Capacity: Please select an image"
        )
        self.capacity_lbl = tk.Label(
            meter_row,
            textvariable=self.encode_capacity_var,
            font=("Segoe UI", 9),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        self.capacity_lbl.pack(side="left")

        self.capacity_bar = ttk.Progressbar(
            meter_row,
            style="Capacity.Horizontal.TProgressbar",
            orient="horizontal",
            length=220,
            mode="determinate",
        )
        self.capacity_bar.pack(side="right", padx=(10, 0))

        # Bottom Section: Password & Action
        bottom_frame = tk.Frame(container, bg=COLOR_CARD_BG, padx=16, pady=12, relief="solid", bd=1)
        bottom_frame.pack(fill="x")

        step3_lbl = tk.Label(
            bottom_frame,
            text="Step 3: Encryption Password (AES-256-GCM via PBKDF2)",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        step3_lbl.pack(anchor="w", pady=(0, 6))

        pwd_grid = tk.Frame(bottom_frame, bg=COLOR_CARD_BG)
        pwd_grid.pack(fill="x", pady=(0, 8))

        # Password
        tk.Label(
            pwd_grid, text="Secret Password:", bg=COLOR_CARD_BG, font=("Segoe UI", 9, "bold")
        ).grid(row=0, column=0, sticky="w", padx=(0, 10), pady=4)
        self.encode_pwd_entry = ttk.Entry(pwd_grid, show="*", width=30)
        self.encode_pwd_entry.grid(row=0, column=1, sticky="w", pady=4)

        # Confirm Password
        tk.Label(
            pwd_grid, text="Confirm Password:", bg=COLOR_CARD_BG, font=("Segoe UI", 9, "bold")
        ).grid(row=0, column=2, sticky="w", padx=(20, 10), pady=4)
        self.encode_confirm_pwd_entry = ttk.Entry(pwd_grid, show="*", width=30)
        self.encode_confirm_pwd_entry.grid(row=0, column=3, sticky="w", pady=4)

        # Show password toggle
        self.encode_show_pwd_var = tk.BooleanVar(value=False)
        show_pwd_chk = ttk.Checkbutton(
            pwd_grid,
            text="Show Passwords",
            variable=self.encode_show_pwd_var,
            command=self._toggle_encode_password_visibility,
        )
        show_pwd_chk.grid(row=1, column=1, sticky="w", pady=(2, 0))

        # Encode Button
        action_row = tk.Frame(bottom_frame, bg=COLOR_CARD_BG)
        action_row.pack(fill="x", pady=(10, 0))

        encode_btn = ttk.Button(
            action_row,
            text="🔒  Encrypt & Save Encoded Image as PNG",
            style="Primary.TButton",
            command=self._handle_encode,
        )
        encode_btn.pack(side="left")

        note_lbl = tk.Label(
            action_row,
            text="💡 Note: The output image is always saved as PNG to preserve LSB bits losslessly.",
            font=("Segoe UI", 8, "italic"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
        )
        note_lbl.pack(side="left", padx=(16, 0))

    def _toggle_encode_password_visibility(self):
        """Toggles masking on password entries in Encode tab."""
        mask = "" if self.encode_show_pwd_var.get() else "*"
        self.encode_pwd_entry.config(show=mask)
        self.encode_confirm_pwd_entry.config(show=mask)

    def _browse_encode_image(self):
        """Handles selecting a carrier image for encoding."""
        file_path = filedialog.askopenfilename(
            title="Select Carrier Image",
            filetypes=[
                ("Supported Image Files", "*.png *.jpg *.jpeg *.bmp *.webp"),
                ("PNG Image (*.png)", "*.png"),
                ("JPEG Image (*.jpg;*.jpeg)", "*.jpg;*.jpeg"),
                ("All Files (*.*)", "*.*"),
            ],
        )
        if not file_path:
            return

        try:
            pil_img = Image.open(file_path)
            # Verify image can be loaded
            pil_img.verify()
            # Reopen for usage since verify() clears data
            pil_img = Image.open(file_path)

            self.encode_carrier_path = file_path
            self.encode_carrier_image = pil_img.convert("RGB")
            self.encode_path_var.set(file_path)

            # Update metrics
            width, height = self.encode_carrier_image.size
            cap_bytes = get_image_capacity(self.encode_carrier_image)
            self.encode_metrics_var.set(
                f"Dimensions: {width} × {height} px ({width * height:,} pixels) | "
                f"Max Capacity: {format_bytes(cap_bytes)} ({cap_bytes:,} bytes)"
            )

            # Update preview thumbnail
            self._update_preview(self.encode_carrier_image, self.encode_preview_lbl)
            self._on_encode_text_changed()
            self.status_var.set(f"Loaded carrier image: {os.path.basename(file_path)}")

        except Exception as e:
            messagebox.showerror(
                "Invalid Image",
                f"Could not open the selected image file.\n\nError: {e}",
            )
            self.encode_carrier_path = None
            self.encode_carrier_image = None
            self.encode_path_var.set("No carrier image selected")
            self.encode_metrics_var.set("Image Dimensions: — | Max Capacity: —")

    def _on_encode_text_changed(self, event=None):
        """Updates the live capacity indicator as the user types secret text."""
        message_text = self.encode_text.get("1.0", tk.END).rstrip("\r\n")
        payload_size = estimate_payload_size(message_text)

        if not self.encode_carrier_image:
            self.encode_capacity_var.set(
                f"Estimated Payload: {format_bytes(payload_size)} | Select carrier image to see capacity"
            )
            self.capacity_lbl.config(fg=COLOR_TEXT_PRIMARY)
            self.capacity_bar["value"] = 0
            return

        max_cap = get_image_capacity(self.encode_carrier_image)
        pct = (payload_size / max_cap) * 100.0 if max_cap > 0 else 0.0

        if payload_size > max_cap:
            self.encode_capacity_var.set(
                f"⚠️ OVER CAPACITY: {format_bytes(payload_size)} / {format_bytes(max_cap)} ({pct:.1f}% used)!"
            )
            self.capacity_lbl.config(fg=COLOR_DANGER)
            self.capacity_bar["value"] = 100
        else:
            self.encode_capacity_var.set(
                f"Payload: {format_bytes(payload_size)} / {format_bytes(max_cap)} ({pct:.2f}% used)"
            )
            self.capacity_lbl.config(fg=COLOR_TEXT_PRIMARY)
            self.capacity_bar["value"] = min(pct, 100.0)

    def _handle_encode(self):
        """Validates inputs, encrypts message, and saves encoded image as PNG."""
        # 1. Validate Image
        if not self.encode_carrier_image:
            messagebox.showwarning(
                "Carrier Image Missing",
                "Please select a carrier image first before attempting to encode.",
            )
            return

        # 2. Validate Message
        secret_msg = self.encode_text.get("1.0", tk.END).rstrip("\r\n")
        if not secret_msg:
            messagebox.showwarning(
                "Secret Message Missing",
                "Please enter a secret message to hide inside the image.",
            )
            self.encode_text.focus_set()
            return

        # 3. Validate Password
        pwd = self.encode_pwd_entry.get()
        confirm_pwd = self.encode_confirm_pwd_entry.get()

        if not pwd:
            messagebox.showwarning(
                "Password Required",
                "Please enter a password to encrypt your secret message.",
            )
            self.encode_pwd_entry.focus_set()
            return

        if pwd != confirm_pwd:
            messagebox.showerror(
                "Password Mismatch",
                "The passwords entered in 'Secret Password' and 'Confirm Password' do not match. "
                "Please re-type them carefully.",
            )
            self.encode_confirm_pwd_entry.focus_set()
            return

        # 4. Prompt user for PNG destination
        default_dir = os.path.dirname(self.encode_carrier_path) if self.encode_carrier_path else ""
        save_path = filedialog.asksaveasfilename(
            title="Save Encoded Steganographic Image",
            initialdir=default_dir,
            initialfile="encoded_secret_image.png",
            defaultextension=".png",
            filetypes=[("Lossless PNG Image (*.png)", "*.png")],
        )
        if not save_path:
            return

        # Force .png extension (prevent accidental JPEG saving)
        if not save_path.lower().endswith(".png"):
            save_path += ".png"

        try:
            self.status_var.set("Encrypting message and embedding into pixels...")
            self.update_idletasks()

            # 5. Perform Encoding
            encoded_img, stats = encode_message_into_image(
                self.encode_carrier_image, secret_msg, pwd
            )

            # 6. Save as PNG
            encoded_img.save(save_path, format="PNG")

            # 7. Success Report
            self.status_var.set(f"Successfully encoded and saved to: {os.path.basename(save_path)}")
            messagebox.showinfo(
                "Encoding Successful",
                f"✅ Your secret message was successfully encrypted and hidden!\n\n"
                f"• Saved To: {save_path}\n"
                f"• Payload Size: {format_bytes(stats['payload_size'])}\n"
                f"• Image Capacity: {format_bytes(stats['total_capacity'])}\n"
                f"• Capacity Used: {stats['used_percentage']:.2f}%\n"
                f"• Encryption: AES-256-GCM (PBKDF2-HMAC-SHA256)\n\n"
                f"Keep your password safe — it is required to extract and decrypt the message!",
            )

        except CapacityExceededError as e:
            messagebox.showerror("Capacity Exceeded", str(e))
            self.status_var.set("Encoding failed: Image capacity exceeded.")
        except CryptoError as e:
            messagebox.showerror("Encryption Error", str(e))
            self.status_var.set("Encoding failed: Cryptographic error.")
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"An unexpected error occurred:\n\n{e}")
            self.status_var.set(f"Encoding error: {e}")

    # =========================================================================
    # DECODE TAB IMPLEMENTATION
    # =========================================================================
    def _build_decode_tab(self, parent):
        """Builds all controls, inputs, and output views for the Decode tab."""
        container = tk.Frame(parent, bg=COLOR_BG)
        container.pack(fill="both", expand=True, padx=8, pady=8)

        # Top section: Image Selection & Preview
        top_frame = tk.Frame(container, bg=COLOR_CARD_BG, padx=16, pady=12, relief="solid", bd=1)
        top_frame.pack(fill="x", pady=(0, 8))

        info_col = tk.Frame(top_frame, bg=COLOR_CARD_BG)
        info_col.pack(side="left", fill="both", expand=True)

        step1_lbl = tk.Label(
            info_col,
            text="Step 1: Select Encoded Image (PNG)",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        step1_lbl.pack(anchor="w")

        browse_btn = ttk.Button(
            info_col,
            text="📁 Browse Encoded Image...",
            style="Secondary.TButton",
            command=self._browse_decode_image,
        )
        browse_btn.pack(anchor="w", pady=(8, 6))

        self.decode_path_var = tk.StringVar(value="No encoded image selected")
        path_lbl = tk.Label(
            info_col,
            textvariable=self.decode_path_var,
            font=("Segoe UI", 9, "italic"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
            wraplength=480,
            justify="left",
        )
        path_lbl.pack(anchor="w", pady=(2, 6))

        self.decode_metrics_var = tk.StringVar(value="Image Dimensions: —")
        metrics_lbl = tk.Label(
            info_col,
            textvariable=self.decode_metrics_var,
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_PRIMARY,
        )
        metrics_lbl.pack(anchor="w")

        # Right: Image Preview Box
        preview_col = tk.Frame(top_frame, bg=COLOR_CARD_BG, padx=8)
        preview_col.pack(side="right")

        self.decode_preview_lbl = tk.Label(
            preview_col,
            text="[ Image Preview ]\nSelect an image to view",
            bg="#F1F5F9",
            fg=COLOR_TEXT_MUTED,
            width=22,
            height=7,
            relief="groove",
            bd=1,
        )
        self.decode_preview_lbl.pack()

        # Middle Section: Password & Action
        mid_frame = tk.Frame(container, bg=COLOR_CARD_BG, padx=16, pady=12, relief="solid", bd=1)
        mid_frame.pack(fill="x", pady=(0, 8))

        step2_lbl = tk.Label(
            mid_frame,
            text="Step 2: Enter Decryption Password",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        step2_lbl.pack(anchor="w", pady=(0, 6))

        pwd_row = tk.Frame(mid_frame, bg=COLOR_CARD_BG)
        pwd_row.pack(fill="x")

        tk.Label(
            pwd_row, text="Password:", bg=COLOR_CARD_BG, font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 10))

        self.decode_pwd_entry = ttk.Entry(pwd_row, show="*", width=35)
        self.decode_pwd_entry.pack(side="left", padx=(0, 12))

        self.decode_show_pwd_var = tk.BooleanVar(value=False)
        show_pwd_chk = ttk.Checkbutton(
            pwd_row,
            text="Show Password",
            variable=self.decode_show_pwd_var,
            command=self._toggle_decode_password_visibility,
        )
        show_pwd_chk.pack(side="left")

        # Action Button
        decode_btn = ttk.Button(
            mid_frame,
            text="🔓  Extract & Decrypt Secret Message",
            style="Primary.TButton",
            command=self._handle_decode,
        )
        decode_btn.pack(anchor="w", pady=(12, 0))

        # Bottom Section: Decrypted Output Result
        out_frame = tk.Frame(container, bg=COLOR_CARD_BG, padx=16, pady=12, relief="solid", bd=1)
        out_frame.pack(fill="both", expand=True)

        res_header = tk.Frame(out_frame, bg=COLOR_CARD_BG)
        res_header.pack(fill="x", pady=(0, 6))

        step3_lbl = tk.Label(
            res_header,
            text="Step 3: Decrypted Secret Message",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        step3_lbl.pack(side="left")

        # Copy & Clear Buttons
        copy_btn = ttk.Button(
            res_header,
            text="📋 Copy to Clipboard",
            style="Secondary.TButton",
            command=self._copy_decrypted_message,
        )
        copy_btn.pack(side="right", padx=(6, 0))

        clear_btn = ttk.Button(
            res_header,
            text="🧹 Clear",
            style="Secondary.TButton",
            command=self._clear_decrypted_message,
        )
        clear_btn.pack(side="right")

        self.decode_result_text = ScrolledText(
            out_frame,
            height=6,
            font=("Consolas", 10),
            wrap="word",
            relief="solid",
            bd=1,
        )
        self.decode_result_text.pack(fill="both", expand=True, pady=(2, 6))

        self.decode_stats_var = tk.StringVar(value="Message length: 0 characters (0 bytes)")
        stats_lbl = tk.Label(
            out_frame,
            textvariable=self.decode_stats_var,
            font=("Segoe UI", 9),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_MUTED,
        )
        stats_lbl.pack(anchor="w")

    def _toggle_decode_password_visibility(self):
        """Toggles password masking on Decode tab."""
        mask = "" if self.decode_show_pwd_var.get() else "*"
        self.decode_pwd_entry.config(show=mask)

    def _browse_decode_image(self):
        """Selects an image to extract and decrypt steganography data from."""
        file_path = filedialog.askopenfilename(
            title="Select Encoded Image",
            filetypes=[
                ("PNG Lossless Images (*.png)", "*.png"),
                ("All Supported Images", "*.png *.jpg *.jpeg *.bmp"),
                ("All Files (*.*)", "*.*"),
            ],
        )
        if not file_path:
            return

        try:
            pil_img = Image.open(file_path)
            pil_img.verify()
            pil_img = Image.open(file_path)

            self.decode_carrier_path = file_path
            self.decode_carrier_image = pil_img.convert("RGB")
            self.decode_path_var.set(file_path)

            w, h = self.decode_carrier_image.size
            self.decode_metrics_var.set(f"Dimensions: {w} × {h} px ({w * h:,} pixels)")

            self._update_preview(self.decode_carrier_image, self.decode_preview_lbl)
            self.status_var.set(f"Loaded encoded image: {os.path.basename(file_path)}")

        except Exception as e:
            messagebox.showerror(
                "Invalid Image",
                f"Could not open the selected image file.\n\nError: {e}",
            )
            self.decode_carrier_path = None
            self.decode_carrier_image = None
            self.decode_path_var.set("No encoded image selected")
            self.decode_metrics_var.set("Image Dimensions: —")

    def _handle_decode(self):
        """Validates inputs, extracts ciphertext from LSB, and decrypts with AES-256."""
        # 1. Validate Image
        if not self.decode_carrier_image:
            messagebox.showwarning(
                "Image Missing",
                "Please select an encoded image first.",
            )
            return

        # 2. Validate Password
        pwd = self.decode_pwd_entry.get()
        if not pwd:
            messagebox.showwarning(
                "Password Missing",
                "Please enter the password used to encrypt the secret message.",
            )
            self.decode_pwd_entry.focus_set()
            return

        try:
            self.status_var.set("Extracting hidden bits and decrypting ciphertext...")
            self.update_idletasks()

            # 3. Extract & Decrypt
            plaintext = decode_message_from_image(self.decode_carrier_image, pwd)

            # 4. Populate Result Area
            self.decode_result_text.delete("1.0", tk.END)
            self.decode_result_text.insert(tk.END, plaintext)

            num_chars = len(plaintext)
            num_bytes = len(plaintext.encode("utf-8"))
            self.decode_stats_var.set(
                f"Message length: {num_chars:,} characters ({format_bytes(num_bytes)})"
            )

            self.status_var.set("Extraction and decryption successful!")
            messagebox.showinfo(
                "Success",
                "🔓 Secret message extracted and decrypted successfully!",
            )

        except SteganographyError as e:
            messagebox.showerror("Steganography Error", str(e))
            self.status_var.set("Decoding failed: No valid steganography signature found.")
        except DecryptionError as e:
            messagebox.showerror(
                "Decryption Failed",
                f"{e}\n\n"
                f"Tips:\n"
                f"• Check for caps lock or typing mistakes in the password.\n"
                f"• Ensure this image was not converted or re-compressed as JPEG.",
            )
            self.status_var.set("Decoding failed: Incorrect password or corrupted payload.")
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"An error occurred while decoding:\n\n{e}")
            self.status_var.set(f"Decoding error: {e}")

    def _copy_decrypted_message(self):
        """Copies the decrypted message to the system clipboard."""
        text = self.decode_result_text.get("1.0", tk.END).rstrip("\r\n")
        if not text:
            messagebox.showinfo("Nothing to Copy", "The decrypted message area is empty.")
            return

        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set("Copied decrypted message to clipboard.")
        messagebox.showinfo("Copied", "Secret message copied to clipboard!")

    def _clear_decrypted_message(self):
        """Clears the decrypted message text area."""
        self.decode_result_text.delete("1.0", tk.END)
        self.decode_stats_var.set("Message length: 0 characters (0 bytes)")
        self.status_var.set("Cleared decrypted message.")

    # =========================================================================
    # PREVIEW & EDUCATIONAL DIALOG HELPERS
    # =========================================================================
    def _update_preview(self, pil_image: Image.Image, label_widget: tk.Label):
        """
        Creates a thumbnail preview preserving the image's aspect ratio
        and displays it inside the given Tkinter Label.
        """
        max_size = (180, 110)
        img_copy = pil_image.copy()
        img_copy.thumbnail(max_size, Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(img_copy)

        # Retain reference so garbage collector does not wipe the image
        label_widget.config(image=photo, text="", width=max_size[0], height=max_size[1])
        label_widget.image = photo

    def _show_how_it_works(self):
        """Opens an educational dialog explaining the math and security concepts."""
        guide = tk.Toplevel(self)
        guide.title("How It Works — Educational Guide")
        guide.geometry("640x520")
        guide.minsize(500, 400)
        guide.configure(bg=COLOR_CARD_BG)

        # Header
        lbl = tk.Label(
            guide,
            text="How Secure Image Steganography Works",
            font=("Segoe UI", 13, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            padx=16,
            pady=12,
        )
        lbl.pack(anchor="w")

        # Scrollable Text
        st = ScrolledText(
            guide,
            wrap="word",
            font=("Segoe UI", 10),
            padx=12,
            pady=8,
            relief="flat",
        )
        st.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        explanation = (
            "1. Cryptography vs. Steganography:\n"
            "   • Cryptography conceals the MEANING of communication.\n"
            "   • Steganography conceals the EXISTENCE of communication.\n"
            "   • Combining both provides defense-in-depth: an outsider looking at the\n"
            "     image sees a normal photograph. Even if they suspect hidden data,\n"
            "     they cannot read it without knowing the AES-256 key.\n\n"
            "2. PBKDF2-HMAC-SHA256 Key Derivation:\n"
            "   • Human passwords vary in length and often lack high entropy.\n"
            "   • We generate a random 16-byte salt and run PBKDF2 with HMAC-SHA256\n"
            "     for 200,000 iterations to derive a uniform 256-bit (32-byte) key.\n"
            "   • This computational work makes dictionary attacks very slow.\n\n"
            "3. AES-256-GCM Authenticated Encryption:\n"
            "   • AES in Galois/Counter Mode (GCM) encrypts the plaintext with a\n"
            "     fresh 12-byte random Nonce.\n"
            "   • GCM produces a 16-byte authentication tag that guarantees integrity.\n"
            "   • If someone enters the wrong password, or if any pixel bit is\n"
            "     altered, the authentication tag fails immediately.\n\n"
            "4. Least Significant Bit (LSB) Steganography:\n"
            "   • In an RGB image, every pixel has 3 color bytes: Red, Green, Blue (0-255).\n"
            "   • The least significant bit (bit 0) alters the channel by ±1 unit.\n"
            "   • This tiny change is visually invisible to human eyes.\n"
            "   • 1 pixel = 3 color channels = 3 bits of secret capacity.\n"
            "   • 8 channels = 1 full byte of payload.\n\n"
            "5. Why PNG is Essential:\n"
            "   • PNG uses lossless compression, preserving every single pixel bit.\n"
            "   • JPEG uses lossy compression that alters pixel values, permanently\n"
            "     corrupting any LSB payload."
        )

        st.insert(tk.END, explanation)
        st.config(state="disabled")

        close_btn = ttk.Button(guide, text="Close", command=guide.destroy)
        close_btn.pack(pady=(0, 12))

    def _show_about(self):
        """Displays About information modal."""
        messagebox.showinfo(
            "About Secure Image Steganography",
            "Secure Image Steganography with AES Encryption\n"
            "Version 1.0 (Educational Project)\n\n"
            "Technologies Used:\n"
            "• Python 3 with Tkinter & ttk (Desktop GUI)\n"
            "• Pillow (PIL) for image handling & LSB bit manipulation\n"
            "• cryptography library (PBKDF2-HMAC-SHA256 & AES-256-GCM)\n\n"
            "Designed for educational demonstration of cryptography and data hiding."
        )
