// script.js

document.addEventListener('DOMContentLoaded', function() {
    // ===== Theme Toggle =====
    const themeToggle = document.getElementById('theme-toggle');
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark');
        if (themeToggle) themeToggle.textContent = '☀️';
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            document.body.classList.toggle('dark');
            const isDark = document.body.classList.contains('dark');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
            this.textContent = isDark ? '☀️' : '🌙';
        });
    }

    // ===== Sidebar Toggle (Mobile) =====
    const menuToggle = document.getElementById('menu-toggle');
    const closeSidebar = document.getElementById('close-sidebar');
    const sidebar = document.getElementById('sidebar');

    function openSidebar() {
        if (sidebar) sidebar.classList.add('open-mobile');
    }
    function closeSidebarFunc() {
        if (sidebar) sidebar.classList.remove('open-mobile');
    }

    if (menuToggle) menuToggle.addEventListener('click', openSidebar);
    if (closeSidebar) closeSidebar.addEventListener('click', closeSidebarFunc);

    // Close sidebar when clicking outside on mobile (if open)
    document.addEventListener('click', function(e) {
        if (window.innerWidth <= 768 && sidebar && sidebar.classList.contains('open-mobile')) {
            const isClickInside = sidebar.contains(e.target) || menuToggle?.contains(e.target);
            if (!isClickInside) {
                closeSidebarFunc();
            }
        }
    });

    // ===== Image Lightbox =====
    window.openImage = function(src) {
        const lightbox = document.getElementById('lightbox');
        const lightboxImg = document.getElementById('lightbox-img');
        if (lightbox && lightboxImg) {
            lightboxImg.src = src;
            lightbox.style.display = 'flex';
        }
    };

    // Close lightbox on click (already set inline, but also allow escape)
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            const lightbox = document.getElementById('lightbox');
            if (lightbox) lightbox.style.display = 'none';
        }
    });

    // ===== File Input - Show File Name =====
    const fileInput = document.querySelector('input[type="file"][name="file"]');
    const fileNameDisplay = document.getElementById('file-name-display');

    if (fileInput && fileNameDisplay) {
        fileInput.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
                fileNameDisplay.textContent = this.files[0].name + ' (' + Math.round(this.files[0].size / 1024) + ' KB)';
            } else {
                fileNameDisplay.textContent = '';
            }
        });
    }

    // ===== Auto-scroll chat to bottom =====
    const messagesContainer = document.getElementById('messages');
    if (messagesContainer) {
        // Scroll to bottom on load
        messagesContainer.scrollTop = messagesContainer.scrollHeight;

        // Optionally observe new messages (if needed, but not critical for standard load)
        // For simplicity, we just scroll on load. If messages are added via AJAX later, adjust.
    }

    // ===== Handle logout form (prevent default) =====
    // The logout link triggers a hidden form submission. We handle it via inline onclick.
    // No extra JS needed.

    // ===== (Optional) Auto-resize textarea? Not needed since we have input type="text" =====
});
