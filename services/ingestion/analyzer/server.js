const http = require('http');

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<h1>사용자 정보</h1><p>연락처: 010-9999-8888</p><p>주민번호: 900101-1234567</p>');
});

server.listen(3000, () => {
  console.log('Node.js 서버가 3000번 포트에서 실행 중입니다.');
});
