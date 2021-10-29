import dns2 from 'dns2';
const { Packet, UDPClient } = dns2;
let nopes = null;

import { join, dirname as getDirname } from 'path';
import { fileURLToPath } from 'url';
const __dirname = getDirname(fileURLToPath(import.meta.url));
import yaml from 'yaml';

import c from 'ansi-colors';
import boxen from 'boxen';

import hasMagic from 'is-glob';
import { promises as fsp, watchFile } from 'fs';
import pm from 'picomatch';

const resolve = UDPClient({ dns: '1.1.1.1' });

const server = dns2.createServer({
  udp: true,
  handle: async (request, send, rinfo) => {
    const response = Packet.createResponseFromRequest(request);
    response.answers.push(...await Promise.all(request.questions.map(async (question) => {
      const { name } = question;
      if (!nopes.some((nope) => nope instanceof Function ? nope(name) : nope === name)) { // individual nope
        const resolved = await resolve(name);
        const { answers, authorities } = resolved;
        const answer = answers[0] || authorities[0]
        // console.log(resolved, request);
        process.stdout.write(`${name} => [8.8.8.8 => ] ${answer.address || answer.domain || answer.primary}\n`);
        return answer;
      } else {
        process.stdout.write(`${name} => [Naughty list => ] 0.0.0.0\n`);
        return {
          name,
          type: Packet.TYPE.A,
          class: Packet.CLASS.IN,
          ttl: 300,
          address: '0.0.0.0'
        };
      }
    })));
    send(response);
  }
});

/* server.on('request', (request, response, rinfo) => {
  // console.log(request.header.id, request.questions);
}); */

server.on('listening', () => {
  // console.log(server.address());
  console.log(c.green(`${c.magenta('[DNS Server]')} DNS server now up and running!`));
});

server.on('close', () => {
  console.log('server closed');
});


const changeNopes = () => {
  const firstTime = nopes === null;
  console.log(c.yellow(`${c.cyan('[Blacklist Loader]')} Now ${firstTime ? 're' : ''}loading the blacklist...`));
  fsp.readFile(join(__dirname, 'nopes.yml'), 'utf-8')
    .then((nopesStr) => {
      let nopesDisplay = yaml.parse(nopesStr);
      console.log(c.green(`${c.cyan('[Blacklist Loader]')} Blacklist now ${firstTime ? 're' : ''}loaded! Now forbidding these domains:`));
      console.log(boxen(c.grey(nopesDisplay.join('\n')), { padding: 1 }));
      if (firstTime) {
        console.log(c.yellow(`${c.magenta('[DNS Server]')} Now loading the DNS server...`));
        server.listen({ udp: 53 });
      }
      nopes = nopesDisplay.map((nope) => hasMagic(nope) ? pm(nope) : nope);
    });
};

changeNopes();

watchFile(join(__dirname, 'nopes.yml'), changeNopes);