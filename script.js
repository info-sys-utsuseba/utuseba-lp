/* ===================================================
   ウツセバ AI活用 感謝特典LP - JavaScript
   =================================================== */

(function () {
  'use strict';

  // ===== フローティングCTAの表示制御 =====
  const floatingCta = document.getElementById('floatingCta');
  const hero = document.querySelector('.hero');

  function updateFloatingCta() {
    if (!hero || !floatingCta) return;
    const heroBottom = hero.getBoundingClientRect().bottom;
    if (heroBottom < 0) {
      floatingCta.classList.add('visible');
    } else {
      floatingCta.classList.remove('visible');
    }
  }

  // ===== スクロールアニメーション =====
  const fadeElements = document.querySelectorAll(
    '.benefit-card, .video-card, .feedback-card, .closing-inner'
  );

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
      threshold: 0.05,
      rootMargin: '0px 0px -20px 0px',
    }
  );

  fadeElements.forEach(function (el) {
    el.classList.add('fade-in');
    observer.observe(el);
  });

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
  });

  // ===== 初期化 =====
  updateFloatingCta();

  // ===== スムーススクロール（アンカーリンク） =====
  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener('click', function (e) {
      const href = this.getAttribute('href');
      // data-placeholder属性があるボタンはスキップ
      if (this.hasAttribute('data-placeholder')) return;
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

  // ===== 仮置きURLボタンのクリック処理 =====
  document.querySelectorAll('[data-placeholder]').forEach(function (btn) {
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      const placeholder = this.getAttribute('data-placeholder');
      // 開発時のみ通知（本番では削除）
      console.log('URL未設定: ' + placeholder);
    });
  });

  // ===== カード遅延アニメーション =====
  document.querySelectorAll('.benefits-grid .benefit-card').forEach(function (card, index) {
    card.style.transitionDelay = (index * 0.08) + 's';
  });

  document.querySelectorAll('.videos-grid .video-card').forEach(function (card, index) {
    card.style.transitionDelay = (index * 0.1) + 's';
  });

})();
