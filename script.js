/* ===================================================
   ウツセバ AI活用 感謝特典LP - JavaScript
   =================================================== */

(function () {
  'use strict';

  // ===== フローティングCTAの表示制御（ヒーロー通過後 + 0.5秒遅延） =====
  const floatingCta = document.getElementById('floatingCta');
  const hero = document.querySelector('.hero');
  let floatingCtaDelay = null;

  function updateFloatingCta() {
    if (!hero || !floatingCta) return;
    const heroBottom = hero.getBoundingClientRect().bottom;
    if (heroBottom < 0) {
      // ヒーローを通過してから0.5秒後に表示
      if (!floatingCta.classList.contains('visible') && !floatingCtaDelay) {
        floatingCtaDelay = setTimeout(function () {
          floatingCta.classList.add('visible');
        }, 500);
      }
    } else {
      // ヒーローが見えている間は非表示
      if (floatingCtaDelay) {
        clearTimeout(floatingCtaDelay);
        floatingCtaDelay = null;
      }
      floatingCta.classList.remove('visible');
    }
  }

  // ===== スクロールアニメーション =====
  // benefit-card-featuredは常に表示（スケールアップのため）
  const fadeElements = document.querySelectorAll(
    '.benefit-card:not(.benefit-card-featured), .video-card, .feedback-card, .closing-inner'
  );

  // featuredカードは初期から表示
  const featuredCard = document.querySelector('.benefit-card-featured');
  if (featuredCard) {
    featuredCard.style.opacity = '1';
    featuredCard.style.transform = 'scale(1.02)';
  }

  const observer = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          // 少し遅延させて確実に表示
          setTimeout(function () {
            entry.target.classList.add('visible');
          }, 50);
          observer.unobserve(entry.target);
        }
      });
    },
    {
      threshold: 0,
      rootMargin: '0px 0px 0px 0px',
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

  // ===== 準備中ボタンのクリック処理 =====
  document.querySelectorAll('[data-placeholder]').forEach(function (btn) {
    btn.addEventListener('click', function (e) {
      e.preventDefault();
    });
  });

  // ===== カード遅延アニメーション（通常カードのみ） =====
  document.querySelectorAll('.benefits-grid .benefit-card:not(.benefit-card-featured)').forEach(function (card, index) {
    card.style.transitionDelay = (index * 0.08) + 's';
  });

  document.querySelectorAll('.videos-grid .video-card').forEach(function (card, index) {
    card.style.transitionDelay = (index * 0.1) + 's';
  });

})();
