'use strict';
'require form';
'require rpc';
'require uci';
'require ui';
'require view';

var callInitAction = rpc.declare({
	object: 'luci',
	method: 'setInitAction',
	params: [ 'name', 'action' ],
	expect: { result: false }
});

function validateAnnounce(value) {
	if (!value)
		return true;
	return /^wss?:\/\/\S+$/.test(value) ? true : _('Expected a ws:// or wss:// URL');
}

function validateSeeds(value) {
	if (!value)
		return true;
	var parts = String(value).trim().split(/\s+/);
	for (var i = 0; i < parts.length; i++) {
		if (!/^wss?:\/\/[^\s|]+(\|[0-9a-fA-F]{64})?$/.test(parts[i]))
			return _('Invalid seed: %s').format(parts[i]);
	}
	return true;
}

function validatePath(value) {
	if (!value)
		return true;
	return value.charAt(0) === '/' ? true : _('Expected an absolute path');
}

return view.extend({
	load: function() {
		return uci.load('dtm_relay');
	},

	render: function() {
		var m = new form.Map('dtm_relay', _('Soty relay'),
			_('LAN relay and tracker for Soty. The same settings are available in /etc/config/dtm_relay.'));
		var s = m.section(form.NamedSection, 'relay', 'relay', _('Relay settings'));
		var o;

		o = s.option(form.DummyValue, '_warning', _('Important'));
		o.rawhtml = true;
		o.default = '<div class="cbi-section-descr">' +
			_('Back up the router before changing settings. The Ed25519 identity file is pinned by clients: never delete or replace it.') +
			'</div>';

		o = s.option(form.Flag, 'enabled', _('Enabled'),
			_('Start the relay automatically when the router boots.'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'port', _('Listen port'),
			_('WebSocket port for the protocol endpoint /ws on the LAN.'));
		o.datatype = 'port';
		o.default = '3100';
		o.rmempty = false;

		o = s.option(form.Value, 'announce', _('Announce URL'),
			_('Public ws:// or wss:// URL advertised to clients. Leave empty to use the router LAN address.'));
		o.placeholder = _('auto');
		o.optional = true;
		o.rmempty = true;
		o.validate = function(section_id, value) {
			return validateAnnounce(value);
		};

		o = s.option(form.DummyValue, '_identity', _('Identity file'));
		// Never render a UCI value as raw HTML: the path is operator-editable
		// and an HTML injection here would run in the LuCI origin.
		o.rawhtml = false;
		o.default = (uci.get('dtm_relay', 'relay', 'identity') ||
			'/etc/dtm-relay/identity') + ' — ' +
			_('Read-only. Changing or deleting this Ed25519 seed creates a new relay identity and breaks every client that pinned this relay.');

		o = s.option(form.Value, 'retention_days', _('Retention, days'),
			_('How long envelopes for subscribed recipients are kept.'));
		o.datatype = 'range(1,3650)';
		o.default = '30';
		o.rmempty = false;

		o = s.option(form.Value, 'max_connections', _('Max connections'),
			_('Simultaneous WebSocket connections. The hard ceiling is 512.'));
		o.datatype = 'range(1,512)';
		o.default = '128';
		o.rmempty = false;

		o = s.option(form.ListValue, 'storage', _('Storage'),
			_('RAM is recommended: router flash wears out and the queue survives a reconnect, not a reboot.'));
		o.value('memory', _('RAM (recommended)'));
		o.value('disk', _('Disk (journal on USB)'));
		o.default = 'memory';
		o.rmempty = false;

		o = s.option(form.Value, 'path', _('Journal directory'),
			_('Only for disk storage. Use a USB mount, for example /mnt/sda1/dtm-relay.'));
		o.placeholder = '/tmp/dtm-relay';
		o.optional = true;
		o.rmempty = true;
		o.depends('storage', 'disk');
		o.validate = function(section_id, value) {
			return validatePath(value);
		};

		o = s.option(form.Flag, 'federation', _('Federation'),
			_('Allow outbound connections to seeded internet relays. Off by default; a LAN relay needs no federation.'));
		o.default = '0';
		o.rmempty = false;

		o = s.option(form.Value, 'seeds', _('Federation seeds'),
			_('Space-separated ws:// or wss:// URLs, optionally pinned with url|ed25519.'));
		o.placeholder = 'wss://relay.example/soty-ws|…';
		o.optional = true;
		o.rmempty = true;
		o.depends('federation', '1');
		o.validate = function(section_id, value) {
			return validateSeeds(value);
		};

		m.handleSaveApply = function(ev, mode) {
			return this.super('handleSaveApply', [ev, mode]).then(function() {
				return callInitAction('dtm_relay', 'restart').then(function(res) {
					if (!res || res.result !== true)
						throw new Error(_('Command failed'));
				}).then(function() {
					ui.addNotification(null,
						E('p', _('Settings saved; the relay was restarted.')), 'info');
				}).catch(function(e) {
					ui.addNotification(null,
						E('p', _('Settings saved, but the relay did not restart: %s').format(e.message)),
						'warning');
				});
			});
		};

		return m.render();
	}
});
