'use strict';
'require view';
'require fs';
'require poll';
'require rpc';
'require uci';
'require ui';

var callInitAction = rpc.declare({
	object: 'luci',
	method: 'setInitAction',
	params: [ 'name', 'action' ],
	expect: { result: false }
});

function getStatus() {
	return fs.exec_direct('/usr/libexec/dtm-relay-status', [], 'text').then(function(res) {
		var data;
		try {
			data = JSON.parse(res || '{}');
		}
		catch (e) {
			return { running: false, error: e.message };
		}
		if (data && data.version)
			data.running = true;
		else if (!data || typeof data !== 'object')
			data = { running: false };
		return data;
	}).catch(function(e) {
		return { running: false, error: e.message };
	});
}

function formatUptime(seconds) {
	var s = Number(seconds) || 0;
	var days = Math.floor(s / 86400);
	var hours = Math.floor((s % 86400) / 3600);
	var minutes = Math.floor((s % 3600) / 60);
	var secs = s % 60;
	if (days > 0)
		return '%d d %d h'.format(days, hours);
	if (hours > 0)
		return '%d h %d min'.format(hours, minutes);
	if (minutes > 0)
		return '%d min %d s'.format(minutes, secs);
	return '%d s'.format(secs);
}

function formatBytes(bytes) {
	var n = Number(bytes) || 0;
	if (n >= 1048576)
		return '%.1f MiB'.format(n / 1048576);
	if (n >= 1024)
		return '%.1f KiB'.format(n / 1024);
	return '%d B'.format(n);
}

function formatNumber(value) {
	return String(Number(value) || 0);
}

function metricRow(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '55%' }, label),
		E('td', { 'class': 'td left' }, value)
	]);
}

function metricCard(title, rows) {
	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, title),
		E('div', { 'class': 'table' }, [
			E('table', { 'class': 'table' }, rows)
		])
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			getStatus(),
			uci.load('dtm_relay')
		]);
	},

	render: function(data) {
		this.status = data[0] || { running: false };
		this.enabled = uci.get('dtm_relay', 'relay', 'enabled') !== '0';
		var running = this.status.running === true;
		var self = this;

		var statusNode = E('div', { 'id': 'dtm-relay-status' }, this.renderStatus());
		var actions = E('div', { 'class': 'cbi-page-actions' }, [
			E('button', {
				'class': 'btn cbi-button cbi-button-positive',
				'disabled': running ? '' : null,
				'click': ui.createHandlerFn(this, function() { return self.service('start'); })
			}, _('Start')),
			E('button', {
				'class': 'btn cbi-button cbi-button-reset',
				'disabled': running ? null : '',
				'click': ui.createHandlerFn(this, function() { return self.service('stop'); })
			}, _('Stop')),
			E('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, function() { return self.service('restart'); })
			}, _('Restart')),
			E('a', {
				'class': 'btn cbi-button',
				'href': L.url('admin', 'services', 'dtm_relay', 'settings')
			}, _('Settings'))
		]);

		poll.add(L.bind(function() {
			return getStatus().then(L.bind(function(status) {
				this.status = status;
				var node = document.getElementById('dtm-relay-status');
				if (node)
					node.replaceChildren(this.renderStatus());
			}, this));
		}, this), 5);

		return E([
			E('h2', {}, _('Soty relay')),
			E('p', { 'class': 'cbi-section-descr' }, _('LAN relay and tracker for Soty.')),
			statusNode,
			actions
		]);
	},

	renderStatus: function() {
		var s = this.status || {};
		var running = s.running === true;
		var service = [
			metricRow(_('State'), running
				? E('span', { 'style': 'font-weight:bold;color:#2e7d32' }, _('Running'))
				: E('span', { 'style': 'font-weight:bold;color:#b00020' }, _('Stopped'))),
			metricRow(_('Autostart'), this.enabled ? _('Enabled') : _('Disabled'))
		];

		if (running) {
			service.push(metricRow(_('Version'), s.version || '—'));
			service.push(metricRow(_('Uptime'), formatUptime(s.uptimeSeconds)));
		}
		if (s.error)
			service.push(metricRow(_('Error'), s.error));

		var cards = [ metricCard(_('Service'), service) ];

		if (running) {
			cards.push(metricCard(_('Connections'), [
				metricRow(_('Now'), formatNumber(s.connections)),
				metricRow(_('Total'), formatNumber(s.connectionsTotal)),
				metricRow(_('Federation links'), formatNumber(s.federatedLinks))
			]));
			cards.push(metricCard(_('Queue'), [
				metricRow(_('Envelopes'), formatNumber(s.envelopes)),
				metricRow(_('Peers'), formatNumber(s.peers)),
				metricRow(_('Subscriptions'), formatNumber(s.subscriptions))
			]));
			cards.push(metricCard(_('Process'), [
				metricRow(_('Memory'), formatBytes(s.rssBytes)),
				metricRow(_('Load 1 min'), s.load1 == null ? '—' : String(s.load1))
			]));
			cards.push(metricCard(_('Counters'), [
				metricRow(_('Received'), formatNumber(s.receivedTotal)),
				metricRow(_('Relayed'), formatNumber(s.relayedTotal)),
				metricRow(_('Rejected'), formatNumber(s.rejectedTotal)),
				metricRow(_('Duplicates'), formatNumber(s.duplicateTotal)),
				metricRow(_('Backfill'), formatNumber(s.backfillTotal)),
				metricRow(_('Live'), formatNumber(s.liveTotal))
			]));
		}
		else {
			cards.push(E('div', { 'class': 'cbi-section' }, [
				E('p', { 'class': 'cbi-section-descr' }, _('Start the relay to see metrics.'))
			]));
		}

		return E('div', {}, cards);
	},

	service: function(action) {
		poll.stop();
		return callInitAction('dtm_relay', action).then(function(res) {
			if (!res || res.result !== true)
				throw new Error(_('Command failed'));
		}).then(L.bind(function() {
			return new Promise(function(resolve) {
				window.setTimeout(resolve, 1200);
			});
		}, this)).then(L.bind(function() {
			return getStatus().then(L.bind(function(status) {
				this.status = status;
				var node = document.getElementById('dtm-relay-status');
				if (node)
					node.replaceChildren(this.renderStatus());
				ui.addNotification(null, E('p', _('Service action completed: %s').format(action)), 'info');
			}, this));
		}, this)).catch(function(e) {
			ui.addNotification(null, E('p', _('Service action failed: %s').format(e.message)), 'danger');
		}).finally(function() {
			poll.start();
		});
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
