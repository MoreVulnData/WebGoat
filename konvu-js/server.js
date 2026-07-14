// Konvu test sinks. Each Express route feeds attacker-controlled request input
// into a vulnerable dependency's sink, so both Dependabot and Konvu's JS
// reachability analysis flag these as reachable/exploitable.
const express = require('express');
const serialize = require('node-serialize');
const _ = require('lodash');
const yaml = require('js-yaml');
const ejs = require('ejs');
const handlebars = require('handlebars');

const app = express();
app.use(express.json());

// CVE-2017-5941: node-serialize.unserialize evaluates an IIFE in the payload -> RCE
app.post('/konvu/node-serialize', (req, res) => {
  const result = serialize.unserialize(req.body.payload);
  res.json({ result: String(result) });
});

// CVE-2021-23337: lodash.template compiles an attacker template -> code execution
app.post('/konvu/lodash', (req, res) => {
  const compiled = _.template(req.body.template);
  res.send(compiled(req.body.data || {}));
});

// CVE-2019-... : js-yaml load() (unsafe in <3.13) instantiates arbitrary types
app.post('/konvu/js-yaml', (req, res) => {
  const doc = yaml.load(req.body.yaml);
  res.json({ doc });
});

// CVE-2022-29078: ejs.render with attacker template/options -> RCE
app.post('/konvu/ejs', (req, res) => {
  const html = ejs.render(req.body.template, req.body.data || {});
  res.send(html);
});

// CVE-2019-19919: handlebars.compile of an attacker template (prototype pollution -> RCE)
app.post('/konvu/handlebars', (req, res) => {
  const template = handlebars.compile(req.body.template);
  res.send(template(req.body.data || {}));
});

app.listen(3000, () => console.log('konvu-js sinks listening on :3000'));
