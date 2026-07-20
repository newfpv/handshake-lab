(() => {
  class NewFPVCredit extends HTMLElement {
    connectedCallback() {
      if (this.shadowRoot) return;
      const href = this.getAttribute('href') || 'https://neewfpv.com/';
      const root = this.attachShadow({mode: 'open'});
      root.innerHTML = `
        <style>
          :host{--credit-accent:var(--accent,#20e4f4);display:inline-block;color:#f4f6f7;font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}
          a{display:flex;min-width:230px;align-items:center;justify-content:space-between;gap:18px;padding:12px 13px 12px 16px;border:1px solid rgba(255,255,255,.12);border-radius:17px;background:linear-gradient(110deg,rgba(255,255,255,.055),color-mix(in srgb,var(--credit-accent) 4.5%,transparent));color:inherit;text-decoration:none;transition:border-color .2s,background .2s,transform .2s}
          a:hover{border-color:color-mix(in srgb,var(--credit-accent) 45%,transparent);background:linear-gradient(110deg,rgba(255,255,255,.075),color-mix(in srgb,var(--credit-accent) 9%,transparent));transform:translateY(-2px)}
          small,strong{display:block}small{margin-bottom:1px;color:#7f898e;font-size:9px;font-weight:800;letter-spacing:.15em;text-transform:uppercase}strong{font-size:13px;letter-spacing:.01em}.mark{color:var(--credit-accent)}
          i{display:grid;width:32px;height:32px;flex:0 0 32px;place-items:center;border:1px solid color-mix(in srgb,var(--credit-accent) 30%,transparent);border-radius:50%;color:var(--credit-accent)}
          svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:2.15;stroke-linecap:round;stroke-linejoin:round}
          @media(max-width:700px){:host{display:block;width:100%}a{min-width:0}}
        </style>
        <a href="${href}" target="_blank" rel="noopener">
          <span><small>Made by</small><strong>New<span class="mark">FPV</span></strong></span>
          <i aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></i>
        </a>`;
    }
  }
  if (!customElements.get('newfpv-credit')) customElements.define('newfpv-credit', NewFPVCredit);
})();
