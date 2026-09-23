/**
 * Animation Helpers
 * Utility functions for smooth transitions and micro-interactions
 */

(function() {
  'use strict';

  /**
   * Animate a number counting up
   */
  window.animateCount = function(element, target, duration = 800) {
    const start = parseInt(element.textContent) || 0;
    const diff = target - start;
    const startTime = performance.now();

    function step(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      element.textContent = Math.round(start + diff * eased);
      if (progress < 1) {
        requestAnimationFrame(step);
      }
    }

    requestAnimationFrame(step);
  };

  /**
   * Stagger-animate child elements
   */
  window.staggerAnimate = function(container, selector, delay = 50) {
    const children = container.querySelectorAll(selector);
    children.forEach((child, i) => {
      child.style.opacity = '0';
      child.style.transform = 'translateY(10px)';
      setTimeout(() => {
        child.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
        child.style.opacity = '1';
        child.style.transform = 'translateY(0)';
      }, i * delay);
    });
  };

  /**
   * Smooth scroll to top
   */
  window.scrollToTop = function(element, smooth = true) {
    element.scrollTo({
      top: 0,
      behavior: smooth ? 'smooth' : 'instant'
    });
  };

  /**
   * Pulse animation for an element
   */
  window.pulseElement = function(element) {
    element.style.animation = 'none';
    element.offsetHeight; // Trigger reflow
    element.style.animation = 'pulse-glow 0.5s ease';
  };

  /**
   * Shrink-fade out an element
   */
  window.fadeOutElement = function(element, duration = 300) {
    return new Promise(resolve => {
      element.style.transition = `opacity ${duration}ms ease, transform ${duration}ms ease`;
      element.style.opacity = '0';
      element.style.transform = 'scale(0.95)';
      setTimeout(resolve, duration);
    });
  };

})();
