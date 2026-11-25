// Notification bell (top right). Opening the menu loads the latest notifications and marks them as read
// (the badge clears); read notifications can then be deleted one by one or all at once.
// Text from the server is only ever set with textContent (no HTML), links must be app-relative.
(function () {
    'use strict';

    const menu = document.querySelector('.lg-bell-menu');
    const button = document.querySelector('.js-bell');
    if (!menu || !button) return;

    const list = menu.querySelector('.lg-bell-list');
    const clearButton = menu.querySelector('.js-bell-clear');
    const badge = document.getElementById('badge-bell');
    const srText = button.querySelector('.js-bell-sr');
    const token = document.querySelector('meta[name="request-verification-token"]')?.content || '';
    const ICONS = { escalation: 'bi-arrow-up-circle', claim: 'bi-person-check', verdict: 'bi-patch-check', comment: 'bi-chat-left-text' };

    function setBadge(count) {
        if (!badge) return;
        badge.querySelector('.count').textContent = count > 99 ? '99+' : String(count);
        badge.classList.toggle('d-none', !(count > 0));
        if (srText) srText.textContent = count > 0 ? `${count} unread` : '';
    }

    function post(url) {
        return fetch(url, {
            method: 'POST',
            headers: { 'RequestVerificationToken': token, 'Accept': 'application/json' },
            credentials: 'same-origin'
        });
    }

    function timeAgo(iso) {
        const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
        if (seconds < 60) return 'just now';
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes} min ago`;
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours} h ago`;
        const days = Math.floor(hours / 24);
        return days === 1 ? 'yesterday' : `${days} days ago`;
    }

    // The server already adds this tab's session prefix (/s/n); only plain local paths become links.
    function safeLink(link) {
        return typeof link === 'string' && link.startsWith('/') && !link.startsWith('//') && !link.startsWith('/\\') ? link : null;
    }

    function empty(text) {
        list.replaceChildren();
        const li = document.createElement('li');
        li.className = 'lg-bell-empty';
        li.textContent = text;
        list.appendChild(li);
        clearButton.disabled = true;
    }

    function render(items, newIds) {
        if (items.length === 0) {
            empty('No notifications. Escalations and verdicts that concern you appear here.');
            return;
        }
        list.replaceChildren();
        for (const n of items) {
            const li = document.createElement('li');
            li.className = 'lg-bell-item' + (newIds.has(n.id) ? ' is-new' : '');
            li.dataset.id = n.id;

            const icon = document.createElement('span');
            icon.className = 'lg-bell-icon';
            icon.setAttribute('aria-hidden', 'true');
            const i = document.createElement('i');
            i.className = 'bi ' + (ICONS[n.kind] || 'bi-info-circle');
            icon.appendChild(i);

            const text = document.createElement(safeLink(n.link) ? 'a' : 'div');
            text.className = 'lg-bell-text';
            if (safeLink(n.link)) text.href = safeLink(n.link);
            const title = document.createElement('span');
            title.className = 'lg-bell-title';
            title.textContent = n.title;
            text.appendChild(title);
            if (n.body) {
                const body = document.createElement('span');
                body.className = 'lg-bell-body';
                body.textContent = n.body;
                text.appendChild(body);
            }
            const time = document.createElement('time');
            time.className = 'lg-bell-time';
            time.dateTime = n.createdAt;
            time.textContent = timeAgo(n.createdAt);
            text.appendChild(time);

            const del = document.createElement('button');
            del.type = 'button';
            del.className = 'lg-bell-delete';
            del.setAttribute('aria-label', 'Delete notification: ' + n.title);
            del.title = 'Delete';
            const x = document.createElement('i');
            x.className = 'bi bi-x-lg';
            x.setAttribute('aria-hidden', 'true');
            del.appendChild(x);
            del.addEventListener('click', () => remove(li, n.id));

            li.append(icon, text, del);
            list.appendChild(li);
        }
        clearButton.disabled = false;
    }

    async function remove(li, id) {
        li.classList.add('is-leaving');
        try {
            const res = await post(`${menu.dataset.delete}/${encodeURIComponent(id)}`);
            if (!res.ok) throw new Error(String(res.status));
            li.remove();
            if (!list.querySelector('.lg-bell-item')) empty('All caught up.');
        } catch {
            li.classList.remove('is-leaving');
        }
    }

    let loading = false;
    async function open() {
        if (loading) return;
        loading = true;
        try {
            const res = await fetch(menu.dataset.list, { headers: { 'Accept': 'application/json' }, cache: 'no-store', credentials: 'same-origin' });
            if (res.status === 401) { empty('Your session in this tab has ended. Reload the page to sign in again.'); return; }
            if (!res.ok) { empty('Notifications could not be loaded. Try again in a moment.'); return; }
            const items = await res.json();
            const unread = new Set(items.filter(n => !n.read).map(n => n.id));
            render(items, unread);
            if (unread.size > 0) {
                // Seen now: the badge clears and every shown notification can be deleted.
                const marked = await post(menu.dataset.read);
                if (marked.ok) setBadge(0);
            }
        } catch {
            empty('Notifications could not be loaded. Try again in a moment.');
        } finally {
            loading = false;
        }
    }

    clearButton.addEventListener('click', async () => {
        clearButton.disabled = true;
        try {
            const res = await post(menu.dataset.clear);
            if (res.ok) empty('All caught up.');
            else clearButton.disabled = false;
        } catch {
            clearButton.disabled = false;
        }
    });

    button.addEventListener('show.bs.dropdown', open);
    // site.js polls the counts every 10 s and draws the badge; keep the screen-reader label in step.
    document.addEventListener('lg:navcounts', e => {
        const count = e.detail?.notifications || 0;
        if (srText) srText.textContent = count > 0 ? `${count} unread` : '';
    });
    empty('Open the bell to load your notifications.');
})();
