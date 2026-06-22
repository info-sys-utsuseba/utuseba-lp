/* ===================================================
   ウツセバ AI活用 感謝特典LP - JavaScript
   =================================================== */

(function () {
  'use strict';

  // ===== フローティングCTAの表示制御 =====
  const floatingCta = document.getElementById('floatingCta');
  const hero = document.querySelector('.hero');
  let floatingCtaShown = false;

  function updateFloatingCta() {
    if (!hero || !floatingCta) return;
    const heroBottom = hero.getBoundingClientRect().bottom;
    if (heroBottom < 0) {
      if (!floatingCtaShown) {
        floatingCtaShown = true;
        setTimeout(function () {
          floatingCta.classList.add('visible');
        }, 400);
      }
    } else {
      floatingCtaShown = false;
      floatingCta.classList.remove('visible');
    }
  }

  // ===== スクロールアニメーション =====
  // rootMarginを大きく取り、画面外でも事前にvisibleにする
  const fadeElements = document.querySelectorAll(
    '.benefit-card:not(.benefit-card-featured), .video-card, .feedback-card, .closing-inner'
  );

  if (typeof IntersectionObserver !== 'undefined') {
    const observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('visible');
            observer.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0,
        rootMargin: '200px 0px 200px 0px', // 上下200px先読み
      }
    );

    fadeElements.forEach(function (el, index) {
      el.classList.add('fade-in');
      el.style.transitionDelay = (index % 5) * 0.06 + 's';
      observer.observe(el);
    });

    // 念のため1秒後に全要素を強制表示
    setTimeout(function () {
      fadeElements.forEach(function (el) {
        el.classList.add('visible');
      });
    }, 1000);

  } else {
    // IntersectionObserver非対応ブラウザは即時表示
    fadeElements.forEach(function (el) {
      el.classList.add('visible');
    });
  }

  // ===== スクロールイベント =====
  let ticking = false;
  window.addEventListener('scroll', function () {
    if (!ticking) {
      requestAnimationFrame(function () {
        updateFloatingCta();
        ticking = false;
      });
      ticking = true;
    }
  }, { passive: true });

  // ===== 初期化 =====
  updateFloatingCta();

  // ===== スムーススクロール =====
  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener('click', function (e) {
      if (this.hasAttribute('data-placeholder')) return;
      const href = this.getAttribute('href');
      if (href === '#') return;
      const target = document.querySelector(href);
      if (target) {
        e.preventDefault();
        const headerHeight = 64;
        const targetTop = target.getBoundingClientRect().top + window.pageYOffset - headerHeight;
        window.scrollTo({ top: targetTop, behavior: 'smooth' });
      }
    });
  });

  // ===== 準備中ボタン =====
  document.querySelectorAll('[data-placeholder]').forEach(function (btn) {
    btn.addEventListener('click', function (e) {
      e.preventDefault();
    });
  });

})();
