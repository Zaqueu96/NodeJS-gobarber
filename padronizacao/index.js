import express from 'express';

class Server {
  constructor() {
    this.server = express();
    this.app = this.server.listen(8080, () => {
      console.log('Server on');
    });
  }
}

export default new Server().app;
