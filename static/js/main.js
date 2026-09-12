/**
 * QR Code Scam Prevention System
 * Main Frontend JavaScript
 */

// ============================================
// Navigation
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    const navbar = document.getElementById('navbar');
    const navToggle = document.getElementById('navToggle');
    const navLinks = document.getElementById('navLinks');

    // Scroll effect
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });

    // Mobile toggle
    if (navToggle) {
        navToggle.addEventListener('click', () => {
            navToggle.classList.toggle('active');
            navLinks.classList.toggle('active');
        });

        // Close mobile menu on link click
        document.querySelectorAll('.nav-links a').forEach(link => {
            link.addEventListener('click', () => {
                navToggle.classList.remove('active');
                navLinks.classList.remove('active');
            });
        });
    }

    // ============================================
    // Make elements visible immediately
    // ============================================
    const reveals = document.querySelectorAll('.reveal');
    reveals.forEach(el => el.classList.add('visible'));

    // ============================================
    // Simple Counters (No animation)
    // ============================================
    const statNumbers = document.querySelectorAll('.stat-number[data-target]');
    statNumbers.forEach(el => {
        const target = parseInt(el.getAttribute('data-target')) || 0;
        el.textContent = target;
    });

    // ============================================
    // Flash message auto-dismiss
    // ============================================
    const flashMsgs = document.querySelectorAll('.flash-msg');
    flashMsgs.forEach(msg => {
        setTimeout(() => {
            msg.style.opacity = '0';
            msg.style.transform = 'translateX(20px)';
            setTimeout(() => msg.remove(), 300);
        }, 4000);
    });
});

// ============================================
// Counter function replaced with simple assignment
// ============================================
function animateCounter(element, start, end, duration) {
    element.textContent = end;
}
