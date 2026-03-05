/**
 * --------------------------------------------------------------------------
 * PARTE 3: UI RENDERER (PRESENTATION LAYER)
 * Manipulación segura del DOM. NUNCA usar innerHTML con datos de usuario.
 * --------------------------------------------------------------------------
 */

// Mixin para funciones de UI dentro de 'app'
Object.assign(app, {

    updateUI: function () {
        const u = this.state.user;
        const panel = document.getElementById('user-panel');
        const display = document.getElementById('user-display');
        const badge = document.getElementById('cart-badge');
        const adminBanner = document.getElementById('admin-banner');

        if (u) {
            panel.classList.remove('hidden');
            // SAFE: textContent
            display.textContent = `${u.username} | ${u.balance.toFixed(2)}€`;
            badge.textContent = this.state.cart.length;

            // Banner Admin
            if (u.role === 'admin') {
                if (adminBanner) adminBanner.classList.remove('hidden');
            } else {
                if (adminBanner) adminBanner.classList.add('hidden');
            }
        } else {
            panel.classList.add('hidden');
            if (adminBanner) adminBanner.classList.add('hidden');
        }
    },

    renderCatalog: function () {
        const grid = document.getElementById('products-grid');
        if (!grid) return;
        grid.innerHTML = ''; // Limpiar contenedor

        const currentUser = this.state.user;
        const isAdmin = currentUser && currentUser.role === 'admin';

        this.state.products.forEach(prod => {
            // Container
            const card = document.createElement('article');
            card.className = 'product-card';

            // Check Ownership
            const isOwner = currentUser && prod.sellerId === currentUser.id;

            // 1. Imagen Segura (con fallback anti-rotura)
            const img = document.createElement('img');
            img.src = prod.image; // Asignación directa a propiedad segura
            img.className = 'product-img';
            img.alt = prod.name;
            img.onerror = function () {
                this.src = 'https://placehold.co/300x200?text=No+Image';
                this.onerror = null; // Evitar loops
            };

            // 2. Título Seguro (Anti-XSS)
            const title = document.createElement('h3');
            title.className = 'product-title';
            title.textContent = prod.name; // IMPORTANTE: textContent

            // 3. Meta info
            const meta = document.createElement('div');
            meta.className = 'product-meta';
            meta.textContent = isOwner ? 'Tu Producto (Venta)' : `Vendedor ID: ${prod.sellerId}`;
            if (isOwner) meta.style.color = 'var(--primary)';

            // 4. Precio
            const price = document.createElement('div');
            price.className = 'product-price';
            price.textContent = `${prod.price.toFixed(2)}€`;

            // 5. Botones de Acción (Context-Aware)
            const footer = document.createElement('div');
            footer.style.marginTop = 'auto';

            if (isAdmin) {
                // CONTROLES DE ADMIN
                const btnEdit = this._createButton('✎ Editar', 'btn-primary', () => this.adminEditProduct(prod.id));
                btnEdit.style.background = '#333';
                btnEdit.style.marginBottom = '5px';

                const btnDel = this._createButton('🗑 Eliminar', 'btn-danger', () => this.adminDeleteProduct(prod.id));

                footer.append(btnEdit, btnDel);
            } else {
                // CONTROLES DE USUARIO
                const btnBuy = this._createButton('Comprar', 'btn-primary', () => this.addToCart(prod.id));

                // Deshabilitar si es el dueño
                if (isOwner) {
                    btnBuy.textContent = 'Es tuyo';
                    btnBuy.disabled = true;
                    btnBuy.style.opacity = '0.5';
                    btnBuy.style.cursor = 'not-allowed';
                    btnBuy.title = "No puedes comprar tus propios productos";
                }

                footer.appendChild(btnBuy);
            }

            card.append(img, title, meta, price, footer);
            grid.appendChild(card);
        });
    },

    toggleCart: function () {
        const modal = this.ui.modal;
        if (modal.hasAttribute('open')) {
            modal.close();
        } else {
            this.renderCart();
            modal.showModal();
        }
    },

    renderCart: function () {
        const container = document.getElementById('cart-items');
        container.innerHTML = '';
        let total = 0;

        if (this.state.cart.length === 0) {
            container.textContent = 'Tu cesta está vacía.';
            container.style.textAlign = 'center';
            container.style.padding = '20px';
        }

        this.state.cart.forEach((item, idx) => {
            total += item.price;

            const row = document.createElement('div');
            row.style.borderBottom = '1px solid #444';
            row.style.padding = '10px 0';
            row.style.display = 'flex';
            row.style.justifyContent = 'space-between';
            row.style.alignItems = 'center';

            const name = document.createElement('span');
            name.textContent = item.name; // Safe

            const right = document.createElement('div');

            const price = document.createElement('strong');
            price.textContent = `${item.price.toFixed(2)}€ `;

            const delBtn = document.createElement('button');
            delBtn.textContent = '✕';
            delBtn.style.background = 'none';
            delBtn.style.border = 'none';
            delBtn.style.color = 'var(--primary)';
            delBtn.style.cursor = 'pointer';
            delBtn.onclick = () => this.removeFromCart(idx);

            right.append(price, delBtn);
            row.append(name, right);
            container.appendChild(row);
        });

        const totalEl = document.getElementById('cart-total');
        if (totalEl) totalEl.textContent = total.toFixed(2);
    },

    // Helper interno para botones rápidos
    _createButton: function (text, className, onClick) {
        const btn = document.createElement('button');
        btn.textContent = text;
        btn.className = className;
        btn.onclick = onClick;
        return btn;
    },

    showToast: function (message, type = 'info') {
        const container = this.ui.toast;
        const t = document.createElement('div');
        t.className = 'toast';
        t.textContent = message;

        // Colores según tipo
        if (type === 'error') t.style.borderLeftColor = 'red';
        if (type === 'success') t.style.borderLeftColor = 'green';

        container.appendChild(t);
        setTimeout(() => t.remove(), 3000);
    }
});

// Arrancar la aplicación
document.addEventListener('DOMContentLoaded', () => {
    app.init();
});
// --- FIN PARTE 3 ---