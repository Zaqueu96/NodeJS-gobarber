# Configurando Sequelize
Primeiro é necessário instalar a dependência **sequelize**
```
  yarn add sequelize
```
E também como dependência de desenvolvimento o **sequelize-cli**, que é uma interface de linha de comando que facilita a criação de migrations, criar models, etc.
```
  yarn add sequelize-cli
```
Feito isso, basta configurar alguns caminhos pro Sequelize:
```
  /src/database/ -> Tudo relacionado ao banco de dados
  /src/database/migrations -> Arquivos de migrations
  /src/config/database.js -> Guarda as configurações do banco de dados
  /src/app/controllers -> Controllers
  /src/app/models -> Models
```
Agora precisamos exportar os caminhos dos arquivos e pastas que foram criados em um arquivo na raíz **.sequelizerc**;
```
  const { resolve } = require('path');

  module.exports = {
    config: resolve(__dirname, 'src', 'config', 'database.js'),
    'models-path': resolve(__dirname, 'src', 'app', 'models'),
    'migrations-path': resolve(__dirname, 'src', 'database', 'migrations'),
    'seeders-path': resolve(__dirname, 'src', 'database', 'seeds')
  }
```
Posso ver os principais [dialects](https://sequelize.org/master/manual/dialects.html) aceitos na documentação. No caso desta aplicação eu preciso instalar mais duas dependências utilizar este dialeto, a _pg_ e a _pg-hstore_.
```
  yarn add pg pg-hstore
```
Agora eu acesso o arquivo src/config/database.js e de dentro dele eu exporto as credenciais.
```
  module.exports = {
    dialect: 'postgres',
    host: 'localhost',
    username: 'postgres',
    password: 'docker',
    database: 'gobarber',
    define: {
      timestamps: true,
      underscored: true,
      underscoredAll: true,
    },
  };
```
O timestamps garante as colunas createdAt e updatedAt dentro de cada tabela do banco de dados, e o underscored significa que quero seguir o padrão como created_at.

### Criando a migration
Para facilitar sem precisar criar toda estrutura do zero, basta usar os recursos do sequelize-cli.

Criando tabela de usuários:
```
  yarn sequelize migration:create --name=create-users 
```
note que dentro da pasta migrations tem um arquivo modelo de migration criado. 
Com o método _up_ para quando a migration for executada e _down_ para o rollback.
```
  module.exports = {
    up: (queryInterface, Sequelize) => queryInterface.createTable('users', {
      id: {
        type: Sequelize.INTEGER,
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
      },
      name: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      email: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true,
      },
      password_hash: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      provider: {
        type: Sequelize.BOOLEAN,
        defaultValue: false,
        allowNull: false,
      },
      created_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      updated_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
    }),

    down: (queryInterface) => queryInterface.dropTable('users'),
  };
```
**Rodando a primeiro migration**
```
  yarn sequelize db:migrate
```
Basta verificar na base de dados e a tabela 'users' já estará criada, inclusive haverá uma tabela chamada SequelizeMeta que irá armazenar todas as migrations que esse banco de dados já recebeu.
**Rollback da última migrate ou de todas**
```
  yarn sequelize db:migrate:undo
```
```
  yarn sequelize db:migrate:undo:all
```

### Models
Primeiro será necessário criar um arquivo _User.js_ na pasta models e importar o Sequelize e o { Model }. Definir uma classe que extende o Model, o método init(sequelize) será chamado automaticamente pelo sequelize. Dentro dele preciso chamar o metodo init() da classe Model e dentro dela vamos enviar as colunas através de um objeto e o sequelize como segundo parâmetro, podemos evitar todas as colunas que são chaves primárias, estrangeiras e até as created_at e updated_at. No final basta exportar o modelo.
```
  import Sequelize, { Model } from 'sequelize';

  class User extends Model {
    static init(sequelize) {
      super.init({
        name: Sequelize.STRING,
        email: Sequelize.STRING,
        password_hash: Sequelize.STRING,
        provider: Sequelize.BOOLEAN
      }, {
        sequelize,
      })
    }
  }

  export default User;
```
> Agora o model já está definido.

### Conexão com o banco de dados
Criar um arquivo dentro da pasta database para realizar a conexão com o banco de dados e também, carregar todos os _models_ da aplicação. Importar o Sequelize (responsável por fazer a conexão), importar também as configurações do banco de dados.

Definir uma classe **Database** e exporta-lo, dentro dela teremos um constructor e um método init() que fará a conexão com a base de dados e carregar os nossos models.
> this.connection = new Sequelize(databaseConfig);
A partir deste momento eu já tenho a conexão com o banco de dados. E essa variável que está sendo esperada dentro do init() dos models. Agora o que preciso fazer é acessar cada model da minha aplicação passando a conexão.
> Vamos importar os models, coloca-los em um array e percorrer passando a conexão para todos os models.
Pra finalizar, preciso chamar essa classe em algúm lugar, como não preciso do retorno, basta chamar na app.js. Não preciso passar o index porque ele chama automaticamente.
```
  import './database';
```
```
  import Sequelize from 'sequelize';
  import User from '../app/models/Users';
  import databaseConfig from '../config/database';

  const models = [User]

  class Database {
    constructor() {
      this.init();
    }

    init() {
      this.connection = new Sequelize(databaseConfig);

      models.map(model => model.init(this.connection));
    }
  }

  export default new Database();

```
Agora vamos testar, importando na rota o model e criando um usuário.

```
  ....
  import User from './app/models/User';

  routes.get('/', async (req, res) => {
    const user = await User.create({
      name: "Klinton Lee"
      email: "klintonlee@email.com.br",
      password_hash: "1234567"
    })

  return res.json(user);
  })
  ....
```

### Cadastro de usuários
Na pasta de controllers, criaremos um arquivo _UserController.js_, como esse controller estará usando o o model de usuário quase sempre, é bom já deixa-lo importado. Basicamente, todo controller de model seguirá esta interface:
```
  import User from '../models/User';

  class UserController {

  }

  export default new UserController();
```
Agora como estarei tratando de cadastro de usuário, dentro da classe eu vou definir uma função que irá receber esses dados, provavelmente, pelo **req.body**. E ela precisa retornar ao usuário uma resposta em formato de JSON.
> Vamos criar um usuário. Posso usar todos os dados que vem do req.body
Afinal, o nosso model já define quais são os campos possíveis. Feito isso eu posso retornar os dados do usuário em forma de JSON.
```
  async store(req, res) {
    const user = await User.create(req.body)

    return res.json(user);
  }
```
Agora preciso criar uma rota no arquivo _routes.js_ com o nome do método.
```
  import UserController from './app/controllers/UserController';

  routes.post('/users', UserController.store);
```
Para testar a aplicação, utilize o **Insomnia** ou o **Postman**
```
  POST : http?//localhost:3333/users

  {
    "name": "Klinton",
    "email": "klinton@email.com.br"
    "password_hash": "123456"

  }
```
No model de usuário definimos o email como **unique: true**, então antes da criação do usuário precisamos montar uma validação para ver se o usuário já não existe. Então voltando na função **store** precisamos declarar antes da criação:
```
  const userExists = await User.findOne({ where: { email: req.body.email } })

  if (userExists) {
    return res.status(400).json({ error: "User already exists" })
  }
```

### Gerando hash do password
Baixar a dependência **bcrypt**, responsável por criptografar a senha.
```
  yarn add bcryptjs
```
Agora lá no model de usuário eu vou precisar importar o bcrypt e criar um novo dado dentro do model, lembrando que estes models não precisam ser um reflexo dos campos da base de dados, são apenas os campos que o usuário poderá preencher. Então vou criar um novo campo **password** e ele será do tipo **VIRTUAL**, que significa um campo que nunca existirá no banco de dados.
```
  import bcrypt from 'bcryptjs';
  ....
  password: Sequelize.VIRTUAL
  ....
```
Antes do final da classe, precisaremos de um novo método **addHook** (funcionalidade do sequelize) que permitirá usar hooks (trechos de código executados automaticamente baseado em ações que acontecem no model).

Como a função executará sempre antes de salvar, precisamos gerar um hash apenas se o usuário informar, pois pode ocorrer do usuário editar os dados, mas não a senha.

Na função bcrypt.hash informamos no primeiro parâmetro o que queremos criptografar e no segundo a força da criptografia.
```
  this.addHook('beforeSave', async user => {
    if (user.password) {
      user.password.hash = await bcrypt.hash(user.password, 8)
    }
  })
```

### JWT (Json Web Token)
É uma metodologia de autenticação em API REST, um token em formato de JSON
##### Autenticação JWT
POST http://api.com/sessions
```
  {
    "email": "klinton@rocketseat.com.br",
    "password": "123456"
  }  
```
Eu vou enviar para esta rota o email e a senha, essa rota fará todas as verificações necessárias, e se tudo estiver correto ela irá gerar um Token JWT.
```
  Um Token é dividido em:               (separadas por ponto)
  Headers(Tipo de Token, algoritmo)     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ
  Payload(Dados adicionais; id, email)  zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4
  Assinatura(chave de segurança)        gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJ
                                        SMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```
### Autenticação na prática
Primeiro criaremos um SessionController.js na pasta de controllers e instalar uma nova dependência, o _jsonwebtoken_.
```
  yarn add jsonwebtoken
```
> mas por que estou criando um novo controller se vou utilizar o User?
Porque estou criando uma Sessão e não um Usuário.

Para checar a senha eu precisaria utilizar o bcrypt, eu poderia importa-lo na SessionController. Mas posso fazer esse método de verificação de senha dentro do Model, porque ele não é bem uma regra de negócio. Então dentro do Model de User posso criar métodos novos dentro da classe, por exemplo: (lembrando que no método bcrypt.compare() o primeiro parâmetro é a senha que o usuário logar e o 
segundo é a senha que o usuário tem na base de dados. O bcrypt retorna true ou false)
```
  checkPassword(password) {
    return bcrypt.compare(password, this.password_hash)
  }
```
```
  import jwt from 'jsonwebtoken';

  import User from '../models/User';

  class SessionController {
    async store (req, res) {
      const { email, password } = req.body;
      const user = await User.findOne({ where: { email } });

      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }

      if (!(await user.checkPassword(password))) {
        return res.status(401).json({ error: password does not match' });
      }

      const { id, name } = user;

      return res.json({
        user: { id, name, email },
        token: jwt.sign({ id }, 'secret', {
          expiresIn: '7d'
        })
      })
    }
  }

  export default new SessionController();
```
Para gerar o token, usamos o jwt.sign()
> 1º parâmetro: payload
> 2º parâmetro: string único (secret)
> 3º parâmetro: configurações (todo token jwt precisa de uma data de expiração)

Feito tudo isso, precisamos definir a rota em routes.js:
```
  import SessionController from './app/controllers/SessionController;

  routes.post('/sessions', SessionController.store)
```
Ao enviar o email e a senha corretamente, os dados serão retornados. Inclusive, o token, e dentro dele estarão todas as informações do exemplo anterior. E usaremos este token mostrarmos que estamos 'autenticados' na aplicação.

É importante separarmos os dados sensíveis do json.sign() dentro de uma pasta 'config' em um arquivo _auth.js_:
```
  export default {
    secret: 'secret',
    expiresIn: '7d'
  }
```
Agora em _SessionController.js_ ficará da seguinte forma:
```
  import authConfig from '../../config/auth';
  ....
  return res.json({
    user: { id, name, email },
    token: jwt.sign({ id }, authConfig.secret, {
      expiresIn: authConfig.expiresIn
    });
  });
```

### Middlewares
Bloquearemos o usuário, caso ele não esteja logado. Consiredemos uma rota de update, não faz sentido para usuários que não estão logados. Lá no UserController precisaremos criar uma nova rota:
```
  ....
  async update(req, res) {
    return res.json({ ok: true });
  }
  ....
```
Depois criar esta rota na routes.js:
```
  ....
  routes.put('/users', UserController.update);
  ....
```
##### Mas como evitar que essa rota seja acessada?
> Utilizando um **middleware**
Primeiro precisaremos aa pasta 'middlewares' dentro do 'app' e criar um arquivo _auth.js_. O que o middleware vai precisar fazer? Basicamente uma verificação se o usuário está logado.

A partir do momento que o usuário foi autorizado, precisaremos utilizar este token em toda próxima requisição. Esse token vai pelo Header da aplicação e por padrão vem seguido de um "Bearer ". Lembrando que o 'next' é importante para continuar a aplicação.

Precisarei importar o jwt e o authConfig (onde está guardado minha secret);

Existe um método dentro do jwt chamado 'verify', com a versão assíncrona e síncrona, mas a versão assíncrona é a melhor a ser utilizada porque manipula a memória e o processamento de uma forma mais legal. Porém, ainda utiliza o padrão antigo de _callback_. Para usar o padrão de async/ await basta importar o método { promisify } do 'util'. Que pega a função de callback e transforma-o para async/ 
await. E do proisify retorna uma função que recebe dois parâmetros, o token e o secret. Por fim, podemos retornar uma nova 'requisição' para as futuras rotas.
```
  import jwt from 'jsonwebtoken';
  import { promisify } from 'util';

  import authConfig from '../../config/auth';

  export default async (req, res, next) => {
    const authHeader = req.headers.authorization

    if (!authHeader) {
      return res.status(401).json({ error: 'Token not provided' });
    }

    const [ , token ] = authHeader.split(' ');

    req.auth = decoded.id;

    return next();
    try {
      const decoded = await promisify(jwt.verify)(token, authConfig.secret);
    } catch (err) {
      return res.status(401).json({ error: 'Token invalid' })
    }
  }
```
> import authMiddleware from './app/middleware/auth';
Posso definir na rota como um middleware de uma rota específica:
> routes.put('/users', authMiddleware, UserController.update)
Ou como middleware global, onde todas as próximas rotas passará por ela
> routes.use(authMiddleware)

### update do usuário
Serial legal para alterar a senha do usuário que o mesmo informe a senha antiga 
```
  {
    "name": "klinton lee"
    "email": "klinton@email.com.br"
    "oldPassword": "123456",
    "password": "159357"
  }
```
Primeira coisa, preciso buscar o **email** e a **oldPassword** de **req.body**. Em seguida buscar o usuário na base de dados, aqui vão algumas verificações como se o usuário (email) já não existe. Então faremos uma verificação para ver se o usuário já não existe. Agora preciso verificar se o usuário deseja alterar a senha e se esta senha bate com a que está cadastrada no banco de dados. Usaremos a verificação que criamos no Model checkPassword().
```
  async update(req, res) {
    const { email, oldPassword } = req.body;
    const user = await User.findByPk(req.auth);

    if (email !== user.email) {
      const userExists = await User.findOne({ where: { email } });

      if (userExists) {
        return res.status(400).json({ error: 'User already exists. });
      }
    }

    if (oldPassword && !(await user.chackPassword(oldPassword))) {
      return res.status(401).json({ error: 'Password does not match' });
    }

    const { id, name, provider } = await user.update(req.body);

    return res.json({ id, name, email, provider });
  }
```

### Validação dos dados de entrada
No cadastro de usuário, não há nenhum tipo de validação como nome sendo obrigatório, etc. É legal essas validações estarem tanto no front-end como no back-end. Existem várias formas de validação, mas utilizaremoso Yup que é uma biblioteca de Schema validation (forma simples de definir os campos que estarão presentes dentro do corpo da requisição (json) e através de funções vou informando o tipo daquele campo (String, required, etc.)).
```
  yarn add yup
```
##### Validação de criação de usuário
O yup não tem um export default, ou seja, não consigo simplesmente importa-lo como
> import Yup from 'yup';
O que faremos é importar tudo que tem dentro do arquivo do 'yup' e colocar dentro de uma variável **Yup**
> import * as Yup from 'yup'
Agora no método de controller, antes de fazer as verificações vamos realizar as validações. Criaremos uma variável chamada **schema** e em seguida declarar o Yup.object(), ou seja, estou validando um objeto, porque o req.body é um objeto. e em seguida o formato que o objeto deve ter .shape(). Definindo o schema precisover se o req.body está passando conforme o esse schema (.isValid(), é assíncrono e retorna true ou false);
```
  async store(req, res) {
    const schema = Yup.object().shape({ 
      name: Yup.string().required(),
      email: Yup.string().email().required(),
      password: Yup.string().required.min(6),
     })

     if (!(await schema.isValid(req.body))) {
       return res.status(400).json({ error: 'Validation fails' });
     }

     ....
  }
```
Existe também a validação condicional .when(), aqui eu tenho acesso as todos os outros campos do Yup. Suponhamos que o usuário quer alterar a senha, quando a oldPassword for preenchida, quero que a senha seja obrigatória: Confirmação da password, quando o 'password' estiver preenchido, eu preciso que o valor seja igual ao campo password.
```
  ....
  oldPassword: Yup.string().min(6),
  password: Yup.string()
    .min(6)
    .when('oldPassword', (oldPassword, field) => {
      return oldPassword ? field.required() : field;
    })
  confirmPassword: Yup.string().when('password', (password, field) => {
    return password ? field.require().oneOf([ Yup.ref('password') ]) : field;
  })
  ....
```

### Upload de arquivos
Primeiro precisamos criar a funcionalidade de upload de arquivos. Optaremos pelo upload de arquivos isolados.

O que aconteceria no cadastro de um usuário comum?
Na hora que ele seleciona a imagem, ela já é enviada ao servidor (o upload já é feito) e o servidor nos retorna um ID daquela imagem. Ou seja, salveremos a imagem(referência dela) pro banco de dados. Aí o servidor retorna lá pro front-end o ID(nome/ código) daquela imagem que foi salva dentro do servidor. E aí na hora que preenchermos com o restante do cadastro, com nome, email e todos os outros dados, a gente envia apenas o ID nesta segunda requisição que foi salvo no servidor. Assim conseguimos manter a estrutura de json para enviar os dados, não precisaremos usar outra estrutura, já que o JSON não suporta envio de upload de arquivos. Então precisaremos de uma biblioteca que seja capaz de lidar com um tipo de corpo diferente, além do formato JSON. Quando precisamos lidar com arquivos nas requisições das nossas chamadas pro servidor. Precisamos enviar estas requisições em um formato **multpart form data**, que é o único formato que suporta envios de arquivos físicos. usaremos o 'multer.
```
  yarn add multer
```
Em seguida criaremos na raíz do projeto uma pastinha chamada 'tmp' e dentro dela uma pastinha chamada 'uploads', onde ficará todos os uploads que fizermos. Agora, dentro de 'src/config' vou criar um arquivo **multer.js** onde ficará toda configuração de upload de arquivos. Importaremos o multer, o crypto (para gerar caracteres aleatórios, etc.), extname(que retorna baseado em uma imagem qual a extensão) e o resolve para definir o caminho.

Do arquivo vou exportar por padrão um objeto com algumas propriedades:
> storage (como o multer vai guardar os nossos arquivos de imagem)
  - Podemos usar vários storages que o multer tem, como o cdn(content delivery network), que são servidores online feitos para armazenamento de arquivos físicos como o amazons3 ou o digital ocean spaces. Mas neste caso guardaremos dentro dos arquivos da aplicação (multer.diskStorage), ele receberá duas propriedades:
  > destination - destino dos nossos arquivos.
  > filename - nome da imagem. Aceita uma função (req, file, callback)
  Mas e se um cliente tiver uma imagem com o mesmo nome de outro cliente ou caracteres diferentes? Então é ideal colocar um código único antes de todas imagens.
> crypto.randomBytes() e passo o número de bytes para gerar e uma callback.
  O callback é a função que precisamos executar com o nome ou com o erro do arquivo se não houver erro, basta passar _null_ como primeiro parâmetro.
```
  import multer from 'multer';
  import crypto from 'crypto';
  import { extname, resolve } from 'path';

  export default { 
    storage: multer.diskStorage({
      destination: resolve(__dirname, '..', '..', 'tmp', 'uploads'),
      filename: (req, file, callback) => {
        crypto.randomBytes(16, (err, res) => {
          if (err) {
            return callback(err);
          }

          return callback(null, res.toString('hex') + extname(file.originalname));
          // Estou trasnformando 16 bytes de conteúdo aleatório em uma string hexadecimal
          // file.originalname é exatamente o nome do arquivo que o usuário deu.
        })
      }
    })
   }
```
Finalizando a configuração do multer, podemos criar nas **routes.js** uma rota
```
  import multer from 'multer';
  import multerConfig from './config/multer.js';
  
  const upload = multer(multerConfig);
  ....
  routes.post('/files', upload.single('file'), (req, res) => {
    return res.json({ ok: true });
  })
```
upload.single() porque quero fazer o upload de um único arquivo por vez e o nome do campo que vou enviar dentro da requisição.

Acessando a rota e fazendo o upload do arquivo é possível ver que a imagem já está na pasta 'tmp/uploads'. A única coisa que não está acontecendo agora é este arquivo estar sendo salvo em algúm lugar(a forma referenciada dele), então eu preciso criar uma tabela do banco de dados para salvar esta referência.

##### Salvando os arquivos dentro da base de dados
Toda vez que o multer está agindo sobre uma rota, ele praticamente libera uma variável pra dentro do req, que se chama req.file. Se eu retorna-lo dentro do res.json(req.file), eu posso ver todos os dados que recebo do arquivo. O originalname e o filename, vou começar criando um **FileController.js** dentro da 
pasta 'controllers' e vou mover a lógica pra dentro do arquivo:
```
  class FileController {
    async store(req, res) {
      return res.json(req.file);
    }
  }

  export default new FileController();
```
Para esse FileController conseguir salvar os arquivos no banco de dados, precisaremos de uma tabela nova no banco de dados.
```
  yarn sequelize migration:create --name=create-files
```
Agora será necessário configrar o migration.
```
  module.exports = {
    up: (queryInterface, Sequelize) => queryInterface.createTable('users', {
      id: {
        type: Sequelize.INTEGER,
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
      },
      name: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      path: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true,
      },
      created_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      updated_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
    }),

    down: (queryInterface) => queryInterface.dropTable('users'),
  };
```
Para finalizar a criação da tabela, basta rodar no terminal:
```
  yarn sequelize db:migrate
```
Para finalizar, precisamos criar um arquivo **File.js** na pasta 'models'
```
  import Sequelize, { Model } from 'sequelize';

  class File extends Model {
    static init(sequelize) {
      super.init(
        {
          name: Sequelize.STRING,
          path: Sequelize.STRING,

        },
        {
          sequelize
        }
      );
      return this;
    }
  }
  export default File;
```
Agora no **index.js** da pasta 'database' eu preciso importar o File para receber o this.connection
```
  import Sequelize from 'sequelize';
  import User from '../app/models/Users';
  import File from '../app/models/File
  import databaseConfig from '../config/database';

  const models = [User, File];

  class Database {
    constructor() {
      this.init();
    }

    init() {
      this.connection = new Sequelize(databaseConfig);

      models.map((model) => model.init(this.connection));
    }
  }

  export default new Database();
```

Agora dentro de **FileController.js** já consigo importar o model de File. O que me importa da req.file é o _originalname_ que salvarei como **name** e o _filename_ de **path** como salvei no model.
```
  class FileController {
    async store (req, res) {
      const { originalname: name, filename: path } = req.file;

      const file = await File.create({ name, path });

      return res.json(file);
    }
  }
```
Agora precisamos criar um relacionamento entre a tabela de usuários com a de arquivos. Ou seja, a tabela de usuários não possui um campo para eu recuperar a informação do arquivo ou associar um usuário com algúm arquivo.

Então precisamos adicionar um campo novo na tabela de usuários. Como a minha tabela de migration já aconteceu. Eu poderia desfazer todas as migrations e adicionar um campo novo. Mas a tabela de arquivos está sendo criada depois, então a nossa tabela não vai conseguir referenciar a tabela de arquivos. Então 
o idela é criar uma migration nova só pra criar essa coluna nova dentro da tabela de usuários.
> yarn sequelize migration:create --name=add-avatar-field-to-users
Adicionando uma coluna na tabela, ao invés de **queryInterface.createTable** usaremos **queryInterface.addColumn**, que receberá qual tabela vou adicionar a coluna, o nome da coluna e um objeto com algumas informações, type: Sequelize.INTEGER, e será **INTEGER** porque vou referenciar o id da imagem e não a imagem em si. E também vou criar uma referência (**references**, foreign key), dentro dela eu passo um objeto, qual o nome da tabela dentro de model e a chave que irei referenciar. Mais duas propriedades não obrigatórias _onUpdate_ e _onDelete_, basicamente, o que irá acontecer com o usuário que tiver o **avatar_id** caso esse arquivo com o mesmo id seja deletado ou alterado. Então se o mesmo for deletado por qualquer motivo lá na tabela Files, o que devo fazer com o avatar_id do usuário. Posso deixa-lo como 'SET NULL' e na edição como 'CASCADE' para que a alteração também ocorra na tabela de usuários.
```
  module.exports = {
    up: (queryInterface, Sequelize) => {
      return queryInterface.addColumn(
        'users',
        'avatar_id',
        {
          type: Sequelize.INTEGER,
          references: { model: 'files', key: 'id' },
          onUpdate: '',
          onDelete: '',
          allowNull: true,
        }
      )
    },

    down: (queryInterface) => {
      return queryInterface.removeColumn('users', 'avatar_id');
    }
  }
```
> yarn sequelize db:migrate
Agora precisamos fazer o relacionamento das tabelas. Na tabela de model do usuário vou criar um método static associate() para receber todos os models da aplicação e usar o método _this.belongsTo()_ que é um tipo de relacionamento
```
  static associate(models) {
    this.belongsTo(models.File, { foreignKey: 'avatar_id' });
  }
  // Aqui eu quero dizer que o model de usuário pertence ao model de File, isso 
  // quer dizer que vou ter um id de arquivo sendo armazenado dentro de meu 
  // model de usuário. Inclusive consigo passar algumas configurações para dizer 
  // qual o nome da coluna dentro da tabela de usuários que vai armazenar a 
  // referência pro arquivo.
```
O hasOne seria o contrário, nós teríamos o id do usuário dentro da tabela de arquivos

No hasMany, teríamos o id do usuário dentro de vários registros. Agora basta chamar esse método de associate. Lá no _index.js_ do database vou fazer um segundo **.map()** dos models
```
  models
    .map(model => model.init(this.connection))
    .map(model => model.associate && model.associate(this.connection.models))
      // Só vou executar o método associate se o 'model.associate' existir, porque
      // nem todo model possui este método.
```

# Lista de prestadores de serviços
Por mais que estejamos tratando ainda de usuário, afinal, o provider é um usuário. Porém, a entidade é outra, estrou tratando diretamente de prestadores de serviços. E a listagem de usuários (UserController) poderia ser utilizada para listar todo tipo de usuário. Então como estou querendo listar apenas a lista de prestadores de serviços eu crio um controller novo.

Criaremos um novo arquivo de controller
  > ProviderController.js
```
  import User from '../models/User';
  import File from '../models/File';

  class ProviderController {
    async index() {
      const providers = await User.findAll({ 
        where: { provider: true } 
        attributes:  ['id', 'name', 'email', 'avatar_id'],
          // Posso escolher quais atributos eu quero que retorne para variável
        include: [
          {
            model: File,
            as: 'avatar',
            attributes: [ 'name', 'path' ]
          }
        ]
          // Ao invés de retornar só o id do avatar (ex: 1), posso retornar um json com o
          // nome 'avatar' e retornando novamente só os atributos interessantes.
      })

      return res.json(providers);
    }
  }

  export default new ProviderController();
```
Agora, precisarei criar na **routes.js** uma rota com o novo controller.
```
  import ProviderController from './app/controllers/ProviderController)
  ....
  routes.get('/providers', ProviderController.index)
```

Só que ao retornar o resultado, não tem nenhuma url com o avatar da imagem, então quando retornar ao front-end ele não saberá como exibir esta informação. Então é interessante o back-end ao retornar estas informações, incluir também uma URL para estas informações.

Então eu volto na pasta 'models', dentro do arquivo **File.js** e criaremos um campo virtual e definir um método get() (como quero formatar este valor), ou seja, todo valor que eu retornar vai aparecer no JSON (front-end). Dentro deste método tenho acesso ao **this**.
```
  ....
    super.init(
      {
        ....
        url: {
          type: Sequelize.VIRTUAL,
          get() {
            return `http://localhost:3333/files/${this.path}`
          }
        }
      }
    )
```
Feito isso no JSON retornará um novo atributo e nela conterá a url informada anteriormente com o nome do arquivo no final. Mas ainda assim ao clicar na URL não retorna nada, para resolver devemos acessar o **app.js** e acrescentar um novo middleware para servir arquivos estáticos (como arquivos de imagem, css, etc.).

```
  middleware() {
    ....
    this.server.use('/files', express.static(path.resolve(__dirname, '..', 'tmp', 'uploads')));
  }
```
Feito isso, ao clicar no link já irá retornar a imagem corretamente.

### Migration e Model de agendamento
  Toda vez que o usuário marcar um agendamento de serviços com alguns dos prestadores ele irá gerar um registro na tabela de agendamento do banco de dados.

Primeiro, vou precisar criar uma migration:
> yarn sequelize migration:create --name=create-appointments
Vou precisar criar dois relacionamentos um para referenciar o usuário com o agendamento, e outro para marcar qual o prestador de serviços que vai atender este agendamento.
```
  module.exports = {
    up: (queryInterface, Sequelize) => queryInterface.createTable('appointments', {
      id: {
        type: Sequelize.INTEGER,
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
      },
      date: {
        allowNull: false,
        Sequelize.DATE,
      },
      user_id: {
        type: Sequelize.INTEGER,
        references: { model: 'users', key: 'id' },
        onUpdate: 'CASCADE',
        onDelete: 'SET NULL',
          // CASCADE - Assim que o usuário for deletado, 
          // todos os agendamentos que este usuário fez também serão.
          // SET NULL - Se o usuário for deletar a conta dele da aplicação, o prestador
          // de serviços vai gostar de manter o histórico dos agendamentos, mesmo que o 
          // usuário não exista mais.
        allowNull: true
      },
      provider_id: {
        type: Sequelize.INTEGER,
        references: { model: 'users', key: 'id' },
        onUpdate: 'CASCADE',
        onDelete: 'SET NULL',
        allowNull: true
      },
      canceled_at: {
        type: Sequelize.DATE,
      },
      created_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      updated_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
    }),

    down: (queryInterface) => queryInterface.dropTable('users'),
  };
```
Finalmente é só rodar o migrate:
> yarn sequelize db:migrate
Feito o migration, precisaremos criar o modelo de appointments na pasta model (Appointment.js);

Não preciso referenciar no model o campo **user_id** nem o **provider_id**, porque ele é gerado automaticamente quando é feito o relacionamento (**associate()**), esse método será chamado automaticamente pelo loader de models na pasta _database_ no arquivo _index.js_.
```
  import Sequelize, { Model } from 'sequelize';

  class Appointments extends Model {
    static init(sequelize) {
      super.init(
        {
          date: Sequelize.DATE,
          canceled_at: Sequelize.DATE
        },
        {
          sequelize
        }
      );
      return this;
    }

    static associate(models) {
      this.belongsTo(models.User, { foreignKey: 'user_id', as 'user' });
      this.belongsTo(models.User, { foreignKey: 'provider_id', as 'provider' });
      // É interessante saber: quando uma tabela tem relacionamentos duas vezes com 
      // outra tabela eu sou obrigado a dar um apelido usando "as".
    }
  }


  export default Appointments;
```

### Rota de agendamento de Serviços
  Começaremos criando um arquivo **AppointmentController.js**:
  ```
    import Appointment from '../models/Appointment';

    class AppointmentController {
      async store(req, res) {
        return res.json({})
      }
    }

    export default new AppointmentController();
  ```
  Também já vou criar uma rota:
  > routes.post('/appointments', AppointmentController.store);
  Feito isso, lá no insomnia criaremos esta rota. Precisamos certificar também que o token seja usuário não prestador de serviços.

  Precisamos enviar o token pelo header da aplicação, lembrando que o usuário deve ser provider: false.
  ```
    {
      "provider_id": 3,
      "date": "2019-07-01T18:00:00-3:00"
        // Podemos passar a data de acordo com a Zona que o usuário está. 
        // Por exemplo: a timezone do Brasil chamamos de UTC-3, para isso basta
        // colocar um "T" antes do horário e -3:00 no final, informarmos UTC-3.
        // Mas podemos enviar em qualquer formado que funcionará normalmente.
    }
  ```
Agora precisamos criar um registro dentro da tabela contendo aquelas informações. Começaremos definindo um schema de validação. Para isso utilizaremoso Yup.
  ```
    import * as Yup from 'yup';
    import User from '../models/User';
    import Appointment from '../models/Appointment';

    class AppointmentController {
      async store(req, res) {
        const schema = Yup.object().shape({
          provider_id: Yup.number().required(),
          date: Yup.date().required()
        });

        if (!(await schema.isValid(req.body))) {
          return res.status(400).json({ error: "Validations fails" });
        }
        
        // Se tudo deu certo, vou precisar do "provider_id" e "date" de dentro req.body.

        const { provider_id, date } = req.body;

        // Preciso verificar primeiro se o id informado realmente é um provider.

        const isProvider = await User.findOne({
          where: { id: provider_id, provider: true }});

        if (!isProvider) {
          res.status(401).json({ "You can only create appointments with providers" })
        }

        // Agora se deu tudo certo e passou pelas verificações, criaremos o agendamento.

        const appointment = await appointment.create({
          user_id: req.userId,
          provider_id,
          date,
        })

        return res.json(appointment);
      }
    }

    export default new AppointmentController();
  ```
Ao criar, notamos que a data. Como informamos a data 18:00:00, porém meu fuso horário é de -3:00. Quando salvou estes dados, automaticamente foi adicionado 3 horas no horário. O Sequelize já lida com esta parte.

## Validações de agendamentos
  Precisaremos verificar se a data que o usuário está tentando marcar já não passou. E a segunda validação é verificar se a data da agenda já não está marcada para este prestador de serviços com um agendamento por 'hora', ou seja, 08:00 às 9:00, não permitindo por exemplo: 8:30.

  Primeiro precisaremos de uma biblioteca que lida com datas, utilizaremos o **date-fns@next**, o @next é para informar que desejo utilizar a versão atual. Mas vou importar apenas alguns métodos. Para isso, ainda no arquivo _Appointments.js_, vou importar o seguinte:
  ```
    import { startOfHour, parseISO, isBefore } from 'date-fns';
    ....
    // logo após a verificação se o usuário é um provider criaremos uma variável.
    const hourStart  = startOfHour(parseISO(date))
    // O que esta startHour vai guardar?
    // basicamente essa parseISO vai guardar a string de dentro de "date" em um
    // Objeto "date" do JavaScript e este objeto pode ser utilizado dentro de
    // startOfHour, que vai pegar apenas o valor da hora e zerar os segundos e
    // minutos.

    if (isBefore(hourStart, new Date())) {
      // Estou comparando se o hourStart está "antes" de new Date().
      // Se essa validação passar significa que a data já passou.
      return res.status(400).json({ error: "Past date are not permitted" });
    }

    // Agora iremos verificar se o prestador de serviços já não possui um horário
    // marcado para o mesmo horário.
    const checkAvailability = await Appointment.findOne({
      where: { 
        provider_id,
        canceled_at: null,
        date: hourStart
      }
    });

    if (checkAvailability) {
      // Se encontrou o "checkAvailability", significa que o horário não está vago.
      return res.status(400).json({ error: "Appointment date is not available" });
    }

  ```
## Listando agendamento do usuário
Mostraremos todos agendamentos o usuário tem e com quais prestadores de serviço.
  > routes.get('/appointments', AppointmentController.index);
  ```
    ....
    import File from '../models/File';
    ....
    async index(req, res) {
      const appointments = await Appointment.findAll({
        where: { user_id: req.userId, canceled_at: null }
        // Precisaremos listar apenas os agendamentos deste usuário que não
        // foram cancelados
      });

      // Encontrado os agendamentos do usuário vou ordena-los por data.
      order: ['date'],

      // Não preciso retornar todas informações do agendamento, apenas id e date
      attributes: ['id', 'date'],

      // Também quero incluir os dados do prestador de serviços. (relacionamento)
      include: [
        {
          model: User,
        // Como o Appointment relaciona com o User duas vezes, preciso informar
        // qual dos relacionamentos quero escolher, as 'provider'
          as 'provider',
        // Como só preciso do id e do name do provider, posso informar attributes
          attributes: [ 'id', 'name' ],
        // Ainda aqui eu vou realizar outro include, porque quero incluir também
        // o avatar do provider.
        include: [
          {
            model: File,
            as: 'avatar,
            attributes: ['id', 'path', 'url']
          }
        ]
        }
      ]
      // Feito isso, posso verificar que o json retornou os os dados do provider
      // e também o avatar. Lembrando que não consigo importar só a 'URL', é
      // preciso do 'id' também do avatar. E também sou obrigado a informar o 
      // 'path', porque a URL depende do path para ser gerado corretamente.

      return res.json(appointments);
    }
  ```
## Paginação
É legal mostrar uma quantidade menor de agendamentos por páginas para usuários
que possuam muitos agendamentos.
### Mas como?
Existe a opção 'Query', para passagem de parâmetros anexado na URL. url/appointments?page=1

Aí eu precisarei pegar essa informação
```
  ....
  index(req, res){
    const { page } = req.query;
    // Se o page não for informado, por padrão o usuário estará na página 1.
    const appointments = await Appointment.findAll({
      ....
      limit: 20,
      offset: (page - 1) * 20,
        // Se eu estiver na página 1, o resutado será (1 - 1) * 20 = 0, ou seja,
        // não pularei nenhum registro. Já na página 2 pularei 20 registros e 
        // listar os próximos 20, que será de 31 ao 40.
      ....
    })
    ....
  }
```

## O que faremos agora é a listar os agendamentos do prestador de serviços.
Então quando o prestador de serviços acessar a aplicação dele para ver quais agendamentos ele tem no dia,
ele precisa ter uma listagem única. Para isso criaremos uma nova rota e um novo controller **ScheduleController.js**.
> import ScheduleController from './app/controller/ScheduleController';
> routes.get('/schedule', ScheduleController.index);
```
  import { startOfDay, endOfDay, parseISO } from 'date-fns';
  import { Op } from 'sequelize';

  import User from '../models/User';
  import Appointment from '../models/Appointment';

  class ScheduleController{
    async index(req, res) {
      
      // 1. Preciso fazer a verificação se o usuário logado é um prestador de serviços
      const checkUserProvider = await User.findOne({
        where: { id: req.userId, provider: true },
          // Lembrando que o req.userId vem pelo header por conta do middleware
      });

      if (!checkUserProvider) {
        res.status(401).json({ error: 'User is not a provider' });
      }

      const { date } = req.query;
      const parsedDate = parseISO(date);

      const appointments = await appointment.findAll({
        where: {
          provider_id: req.userId,
          canceled_at: null,
          date: {
          // Para data precisarei fazer uma verificação(operação between),
          // basicamente vou pegar a primeira hora do dia que seria 00:00:00
          // e a última hora do dia, e vou ver todos agendamentos que estão
          // entre aqueles valores. Mas como? A biblioteca do 'date-fns' possui
          // os operadores startOfDay e endOfDay. Por isso começaremos importando-os.
          // Inclusive o parseISO para transformar a data de String para Objeto.
          // Importaremos também o operador do Sequelize, boas práticas.
            [Op.between]: [startOfDay(parsedDate), endOfDay(parsedDate)],
              // Preciso coloca-los em volta de colchetes, por se tratar de uma variável e
              // eu precisar do nome da propriedade deste objeto como nome pra chave no meu
              // objeto. E o valor será um array com os dois valores que eu preciso comparar.
          },
          order: ['date']
            // Por fim iremos ordena-los por data.
        }
      })

      return res.json(appointments);
    }
  }

  export default new ScheduleController();
```

Agora lá no insomnia criamos a pasta _Schedule_, pois crio uma pasta para cada controller. Em seguida, um método index.

Feito isso, preciso garantir que estou logado como um prestador de serviços. Então voltando nas _Sessions_ vou informar o email e a senha para retornar um token **JWT**. Vou copiar o token e colocar no Bearer da ScheduleController.index

  Quando nos referimos ao prestador de serviços, o que mais importa são os agendamentos do dia, sendo menos importante os dias que passaram e os dias futuros. Para isso enviaremos nos Query Params a data que ele quer visualizar, e assim listar todos agendamentos daquele dia.
  > New name: date
  > New value: 2019-06-22T00:00:00-3:00
  da const { date } vou utilizar apenas o dia e o horário

# Configurando o MongoDB
Utilizaremos um banco não relacional, porque teremos alguns dados que não serão estruturados e não terão relacionamentos e precisam ser extremamente performáticos. Ele também possui um ORM, o mongoose. Por isso começaremos usando o docker para subir um container rodando a imagem do MongoDB.
> docker run --name mongobarber -p 27017:27017 -d -t mongo
### E agora, como que eu faço para conectar a aplicação ao mongoDB?
Começaremos baixando a dependência _mongoose_
> yarn add mongoose
E agora vou utilizar o mesmo _index_ que utilizamos na pasta _database_. No arquivo eu já tenho um método init(), então criarei um segundo método
```
  import mongoose from 'mongoose';
  ....
  class Database {
    constructor(){
      ....
      this.mongo();
    }
    ....
    mongo() {
      this.mongooseConnection = mongoose.connect(
        'mongodb://localhost:27017/gobarber',
        { useNewUrlParser: true, useFindAndModify: true }
      )
    }
  }
```

### Notificando novos agendamentos.
  O que faremos agora é enviar uma notificação ao prestador de serviços, toda vez que receber um novo agendamento. Para isso usaremos o MongoDB, armazenaremos as notificações dentro do Mongo.
  
  Mas antes precisaremos criar um novo Schema dentro do mongo. Que seria como o model que representa uma tabela, mas também teremos uma pasta chamada **schemas**, que são models, porém, representados através de schemas. Porque no mongo não possuímos tabelas e sim schemas, que são quase a mesma coisa. A grande diferença é que nas tabelas os dados são estruturados, ou seja, a coluna das tabelas são iguais para todos os dados, pra todos os registros da tabela.

  Dentro do MongoDB, há uma metodologia que se chama _schema free_, um registro que eu salvo pode ter uma informação enquanto o outro registro não. E também no Mongo não teremos as migrations, poderemos alterar os schemas no momento que desejarmos, mas precisa sempre ateção, pois se removermos um campo ele não poderá mais ser obtido. Por isso é necessário atenção nos processos de migração no mongo.

  Utilizaremos o mongo para o salvar as notificaçãos, pois basicamente elas não possuem muitos relacionamentos, ela irá apenas relacionar-se com o _id_ do usuário. Ou seja, qual prestador de serviços vou enviar a notificação.

  Vou começar criando uma pasta **schemas** dentro da pasta _app_, com um arquivo **Notification.js**.
  ```
    import mongoose from 'mongoose';

    const NotificationSchema = new mongoose.Schema({
      // Aqui dentro eu defino os campos, mesmo que estes schemas possam variar 
      // muito de acordo com o tamanho da aplicação e com o tempo da aplicação no
      // ar, preciso importar pelo menos os campos principais que utilizarei pro
      // javascript, na hora que estiver salvando os dados dentro do schema, ele
      // saiba quais campos ele pode adicionar lá dentro.
      content: {
        type: String,
        required: true,
      },
      user: {
        type: Number,
          // O ID do usuário está em Integer, por isso utilizaremos Number no mongo
        required: true,
      },
      read: {
        // Verifica se a notificação foi lida ou não
        type: Boolean,
        required: true,
        default: false,
      }
    }, {
      timestamps: true,
        // também quero os campos created_at e updated_at por padrão em todos registros
    });

    export default mongoose.model('Notification', NotificationSchema);
  ```
  Diferente do Sequelize, no mongo eu posso simplesmente importar o Schema e sair utilizando.

  Agora no arquivo **AppointmentController.js** no momento em que criamos um novo agendamento, iremos também notificar o prestador de serviços.
  ```
    ....
    import Notification from '../schemas/Notification';

    class AppointmentController {
      ....
      const user = await User.findByPk(req.userId);
        // O nome do usuário podemos pegar de Req.userId.

      // A gente já tem uma variável hourStart que é exatamente a data que o 
      // agendamento vai ser prestado. Porém preciso dar uma formatada nele.
      // Usaremos novamente o date-fns, importando o { format } que nos dá 
      // liberdade para formatarmos a data da forma que desejarmos.
      const formattedDate = format(
        hourStart,
        "'dia' dd 'de' MMMM', às' H:mm'h'",
          // O 'd' representa o dia. Então se eu escrever 'dia', ele irá trocar
          // para '22ia', Por isso precisarei usar Aspas duplas e aí no date-fns
          // todo lugar que usarmos aspas simples ele não trabalha como string
          // Então se eu escrever "'dia'", a string não sofrerá a formatação.
          // 'dd' significa o dia completo (dois digitos)
          // 'MMMM' vai substituir o mês por extenso. Porém, esse mês precisa ser
          // traduzido para o mês por extendo em português. Por isso, precisaremos
          // importar o locale do date fns para o terceiro parâmetro do format()
          ////// import pt from 'date-fns/locale/pt'; //////
        { locale: pt }
      )
        // Primeiro parâmetro vai a data que desejamos formatar.
        // Segundo parâmetro vai o formato.
        // Terceiro parâmetro vai um objeto com a localidade.

      await Notification.create({
        // Aqui dentro passo os campos
        content: `Novo agendamento de ${user.name} para ${formattedDate}.`,
        user: provider_id,
        // Não precisaremos definir o 'read' porque já existe um valor default.
      });
    }
  ```
  Uma coisa que deve ser fixado em nossa cabeça, é que no momento que utilizamos um banco não relacional, algumas coisas é legal não mantermos relacionamento. Por exemplo: o conteúdo posso escrever exatamente:
  > Novo agendamento de Klinton Lee para dia 22 de Junho as 8h40
  Não iremos armazenar o **id** do usuário(Klinton Lee) para o prestador de serviços, mesmo que o usuário venha alterar futuramente o nome para **Klin**, ainda irá permanecer _Klinton Lee_ de forma estática no momento que a notificação foi gerada. Porque a mensagem é salva dentro do MongoDB exatamente como estava o estado naquele momento. Assim garantimos muita performace. O mesmo serve para a data e o horário.

  O único relacionamento que irei armazenar é _qual o prestador_ precisará receber esta notificação, porque na hora de listarmos os agendamentos precisaremos deste filtro.

  Para visualizarmos nossos dados no MongoDB podemos utilizar o mongoDB Compass Community, ao instalar o aplicativo, basta preencher o dados corretamente e dar um **Connect**, na lateral esquerda aparecerá os databases, mas nesta aplicação criaremos uma nova, pois como não inserimos nenhum registro ainda, o Mongo não criou a nova database que fizemos na conexão **(index.js na pasta database)**.

  Para testarmos, basta ir em Appointments lá no Insomnia e tentar criar um novo agendamento. Ao criar o agendamento, como eu sei que o Mongo criou a notificação? Basta ir no MongoDB Compass Community e dar um refresh.

### Listando as notificações do usuário.
  O que faremos agora, é listar todas as notificações do prestador de serviços. Para isso começaremos criando uma nova rota e um novo controller **NotificationController.js**:
  > import NotificationController from './app/controllers/NotificationController';
  > routes.get('/notifications', NotificationController.index);
  ```
    import User from '../models/User';
    import Notification from '../schemas/Notification';

    class NotificationController {
      async index(req, res) {
      // esta rota só poderá ser acessada por prestadores de serviços.
        const checkIsProvider = await User.findOne({
          where: { id: req.userId, provider: true },
            //Estou verificando e o usuário 'logado' é um prestador de serviços.
        });

        if (!checkIsProvider) {
          return res.status(401).json({ error: 'Only provider car load notifications' });
        }

      // Feito a verificação, precisaremos listar as notificações.
        const notifications = await Notification.find({
          // Aqui dentro passo os filtros para buscar as 'Notificações'
          user: req.userId,
        })
        .sort({ createdAt: -1 })
          // Ordena por data de criação (em decrescente)
        .limit(20);
          // Limita o número de resultados para as últimas 20 notificações.
        
        return res.json(notifications);
      }
    }

    export default new NotificationController();
  ```
  Lá no insomnia criaremos uma nova pasta **Notification** com um **index(List)** para utilizarmos a rota criada, Lembrando que será necessário enviar a _autenticação (JWT)_.

  Assim que logarmos com o prestador de serviços, ao acessar a rota **get** as notificações irão retornar.

### Marcar notificações como lidas
  Começaremos criando uma nova rota e adicionando uma rota update em **NotificationController.js**
  > routes.put('/notifications/:id', NotificationController.update);
  ```
    ....
    class NotificationController {
      ....
      async update(req, res) {
        // Primeiro de tudo, precisaremos buscar a notificação no banco de dados.
          const notification = await Notification.findByIdAndUpdate(
            req.params.id,
            { read: true },
            { new: true } 
              // Depois de atualizar, ele irá retornar a 'nova' notificação
          );
      }
      // Pronto, enviando a requisição com o ID da notificação e a propriedade 
      // read passa a ser true.
    }
    ....
  ```
### Cancelamento do agendamento
  O usuário que fez o agendamento poderá cancelar o agendamento que ele fez. Porém, ele só poderá cancelar se estiver a duas horas de distância do horário marcado. Para isso começaremos criando uma nova rota de 'appointments':
  > routes.delete('/appointments/:id', AppointmentController.delete);
  Agora abro o arquivo de AppointmentController e crio um novo método:
  ```
    ....
    class AppointmentController {
      ....
      async delete (req, res) {
        // Primeiro preciso buscar os dados do agendamento.
        const appointment = await Appointment.findByPk(req.params.id);

        if ( appointment.user_id !== req.userId) {
          return res.status(401).json({
            error: "You don't have permission to cancel this appointment."
          });
        }

        // Agora precisamos fazer a verificação de cancelar em até 2h antes.
        // Começaremos importando um método do 'date-fns', o { subHours },
        // que reduz o número de horas de um horário da data.

        const dateWithSub = subHours(appointment.date, 2);
          // Agora preciso verificar se o horário menos as 2 horas continua sendo
          // menor que agora. Por exemplo:
          // agendamento: 13:00
          // dateWithSub: 11:00
          // new Date() : 11:25
          // Significa que o prazo para cancelamento já expirou.

        if (isBefore(dateWithSub, new Date())) {
          return res.status(401).json({
            error: 'You can only cancel appointments 2 houras in advance
          });
        }

        // Preciso setar diretamente o valor no campo de cancelamento do appointment:
        appointment.canceled_at = new Date();
          // Agora a data atual está neste campo.

        await appointment.save();
        return res.json(appointment);
      }
    }
  ```
# Nodemailer
  Como o cancelamento é bem importante para o prestador de serviços se precaver, enviaremos um email para este prestador de serviços. Para isso precisaremos configurar algumas bibliotecas de envio de email, começando pelo **nodemailer**
  > yarn add nodemailer
  Agora precisaremos criar um arquivo **mail.js** dentro da pasta config e de dentro vou exportar um objeto contento várias configurações para envios de email.
  ```
    export default {
      host: '',
      port: '',
        // porque vou enviar o email através do SMTP (Simple Mail Transfer Protocol)
      secure: false,
        // informar se está utilizando SSL ou não.
      auth: {
        user: '',
          // email
        password: ''
          // senha
      },
      default: {
        // Aqui eu defino algumas configurações padrão.
        from: 'Equipe GoBarber <noreply@gobarber.com>'
      }
    }
  ```
###  Mas afinal, onde consigo o host, port, user e pass?
  Existem vários serviços que podemos utilizar, como o Amazon SES, Mailgun, Sparkpost, etc. Não é legal utilizarmos o SMTP do próprio Gmail, porque ele tem um limite e pode vir a bloquear. Para estudo utilizaremos o [Mailtrap](https://mailtrap.io/), que serve simplesmente para ambiente de desenvolvimento, ou seja, não funcionará quando a aplicação estiver online.
  ##### Como começar?
  Haverá um input para o nome do Inbox e um botão de criação, em seguida basta acessada na lista de Inboxes. Ao abrir o link aparecerá as credenciais para as configurações do **mail.js**. Exemplo:
  > host: 'smtp.mailtrap.io'
  > port: 2525
  > user: '6ec4fee1bf1760'
  > pass: '645360c7b881a1'
  Agora precisamos enviar o nosso email, precisaremos de algumas configurações a mais.
  Vou criar uma pasta **lib** em **src**, onde irei configurar coisas adicionais da aplicação. Por exemplo, envio de email não precisa ser feito de um controller, o controller vai apenas enviar um email dentro de appointments no cancelamento. Mas se eu precisar fazer alguma configuração no email como o remetente padrão, eu sempre preciso fazer isso dentro de uma parte mais isolada, para isso eu crio uma pasta lib com um arquivo **Mail.js**.
  ```
    import nodemailer from 'nodemailer';
    import mailConfig from '../config/mail';

    class Mail {
      constructor() {
        const { host, port, secure, auth } = mailConfig;

        this.transporter = nodemailer.createTransport({
          // trasnporter: como o nodemailer chama uma conexão com algúm serviço 
          // externo para envio de emails
            host,
            port,
            secure,
            auth: auth.user ? auth : null
              //Vou verificar se existe um auth.user, senão vou passar como nulo.
              // Porque existe algumas estratégias para envio de email que ele não
              // possui autenticação, usa-se apenas o host, port e o secure.
        })   
      }

      sendMail(message) {
        return this.transporter.sendMail({
          ...mailConfig.default,
          ...message,
        });
          // Por que criei um novo método e não usei o próprio constructor?
          // Porque defini algumas variáveis padrão como "from: 'Equipe'...."
          // Então pegarei todos os dados que são padrão e somar com os dados que
          // recebo da minha mensagem lá do controller.
      }
    }

    export default new Mail();
  ```
  Feito isso, vou em **AppointmentController**, importo as configurações do Mail
  ```
    ....
    import Mail from '../../lib/Mail';
    class AppointmentController {
      ....
      async delete (req, res) {
        const appointment = await Appointment.findByPk(req.params.id, {
          include: [
            {
              model: User,
              as: 'provider',
                // Como o appointment possui relacionamento com o User duas vezes,
                // preciso utilizar o as para retornar os dados do provider.
              attributes: [ 'name', 'email' ]
                // E as únicas informações que me interessam do provider são o 
                // nome e o email.
            }
          ],
            // Posso dar um include (array) para ele incluir as informações 
            // também do prestador de serviços.
        }) 
        ....
        await Mail.sendMail({
          to: `${appointment.provider.name} <${appointment.provider.email}>`,
            // Preciso enviar ao prestador de serviços.
          subject: 'Agendamento cancelado',
          text: 'Você tem um novo cancelamento',
            // Podemos utilizar em forma de html também.
        })
        return ....
      }
    ....
  ```
## Configurando templates de e-mail
  Template engine são arquivos html, para envio de emails mais personalizados usando HTML e CSS, para isso precisarei instalar duas extensões. Template engines também podem receber variáveis do Node. Utilizaremos o **handlebars** adicionando o **express-handlebars** e o **nodemailer-express-handlebars**
  > yarn add express-handlebars nodemailer-express-handlebars
  Agora no arquivo **Mail.js** da pasta _lib_ iremos setar algumas configurações:
  ```
    ....
    import { resolve } from 'path';
    import exphbs from 'express-handlebars';
    import nodemailerhbs from 'nodemailer-express-handlebars';

    class Mail {
      constructor() {
        ....
        this.configureTemplates();
      }
      configureTemplates() {
        // começarei definindo um caminho dos templates. Que estarão na pasta 
        // 'views' dentro da pasta 'app'
        const viewPath = resolve(__dirname, '..', 'app', 'views', 'emails');

        this.transporter.use('compile', nodemailerhbs({
          viewEngine: exphbs.create({
            layoutsDir: resolve(viewPath, 'layouts'),
            partialsDir: resolve(viewPath, 'partials'),
            defaultLayout: 'default',
              // Aí eu posso criar dentro de layouts o arquivo default.hbs
            extname: '.hbs'
              // Qual extensão estou utilizando nos arquivos.
          }),
          viewPath,
          extName: '.hbs'
        }))
          // O compile é como ele formata os nossos templates
      }
    }
  ```
  Dentro da pasta **app** vou configurar uma pasta **views**, dentro uma pasta **emails** e dentro duas pastas **layouts** e **partials** e um arquivo **cancellation.handlebars**

  Finalizado, as nossas templates já estão configuradas. Agora como utilizar?
  
  Primeiramente vou configurar o layout _default.hbs_, será o layout utilizado para todos envios de email.
  ```
    <div style="
      font-family: Arial, Helvetica, sans-serif; 
      font-size: 16px;
      line-height: 1.6;
      color: #222;
      max-width: 600px;">

    // Agora como eu quero que o corpo da mensagem venha dentro desta <div>, 
    // basta eu colocar 3 chaves {{{ body }}}, agora o handlebars sabe por padrão
    // que o conteúdo da mensagem vai alí dentro.

    {{{ body }}}

    // Agora para importar um partials, utilizo duas chaves com um sinal de maior
    // e o nome do partials.
    {{> footer }}
    
    </div>
  ```
  Agora sobre os partials, são arquivos que eu posso implementar dentro de alguns emails. Por exemplo, poderia criar um partials com algúm tipo de mensagem específica que será repetida em vários emails. E esse partials posso importar para dentro de cada email. Digamos que eu queira criar um footer para o meu email. Dentro de partials criarei um arquivo **footer.hbs**.
  ```
    <br />
    Equipe GoBarber
  ```
  #### Trabalhando no layout de cancelamento
  ```
    <strong>Olá, {{ provider }}</strong>
    <p>Houve um cancelamento de horário, confira os detalhes abaixo: </p>
    <p>
      <strong>Cliente: </strong> {{ user }} <br />
      <strong>Data/hora: </strong> {{ date }} <br />
      <br />
      <small>
        O horário está novamente disponível para novos agendamentos.
      </small>
    </p>
  ```
  Agora lá em AppointmentController, preciso incluir as variáveis, lá no método delete em **await Mail.sendmail...** trocaremos por:
  ```
    await Mail.sendMail({
      to: `${appointment.provider.name} <${appointment.provider.email}>`,
      subject: 'Agendamento cancelado',
      template: 'cancellation',
        // Aqui preciso passar qual template estou utilizando
      context: {
        // Aqui eu envio todas as variáveis que o cancellation.hbs está esperando.
        provider: appointment.provider.name,
        user: appointment.user.name,
          // Eu posso incluir na constante 'appointment' o model: User, 
          // as 'user' e nos attributes, apenas o [ 'name' ]
        date: format(
          appointment.date,
          "'dia' dd 'de' MMMM', às' H:mm'h'",
          { locale: pt }
          // Aqui precisamos fazer a formatação mais ou menos igual aquela que
          // fizemos na criação de um novo agendamento. Por isso usarei o mesmo
          // método format()
        );
      }
    })
  ```

## Configurando fila com Redis
  Uma coisa que podemos notar é que ao enviar o email, essa rota demoram alguns segundos para responder, enquanto que as outras rotas levam milésimos para responder. Mas afinal, como diminuir o tempo de resposta? E mesmo assim esse e-mail ser enviado pelo Node?
  
  Existem duas formas de fazer isso: 
  - Podemos simplesmente tirar o _await_ do **Mail.sendMail({....})**, assim ele não aguardará o email ser enviado para retornar a resposta. E mesmo assim, ele irá enviar o email.
  ##### Mas quais as desvantagens de fazer isso?
  No momento que tiramos o _await_, se ocorrer um erro, jamais saberemos sobre ele. Porque já retornamos a resposta ao cliente (que já deu tudo certo.), então desta forma perdemos totalmente o controle. Então a melhor forma de controlarmos ações que levam um pouco mais de tempo e elas não precisam exatamente finalizar no mesmo momento que damos a resposta ao cliente, mas mesmo assim queremos ter controle destas ações (ok, erro, re-tentativa, prioridades, etc.). A melhor forma é através de um recurso chamado **filas** ou **background-jobs**, ou seja, conseguimos configurar dentro da aplicação alguns tipos de serviços que ficam rodando em segundo plano que executam estes trabalhos que levam mais tempo, mas que não modificar a resposta ao da-la pro cliente.
  ##### Mas como configurar estes background-jobs?
  Precisaremos antes de mais nada, um banco chave: valor e neste caso usaremos o **Redis**, que é um banco não relacional, mas diferente do MongoDB no Redis não conseguimos ter schemas, estruturas de dados e apenas conseguimos salvar chave e valor. Ou seja, ele vai ser muito mais performático e permitirá cadastrar milhares de registros sem perder qualquer tipo de performace.
  ##### Startando o Redis
  > docker run --name redisbarber -p 6379:6379 -d -t redis:alpine
  Agora precisaremos baixar o [bee-queue](https://github.com/bee-queue/bee-queue) que basicamente é uma ferramenta de fila dentro do Node, extremamente performático. Porém, ele não possui todas as funcionalidades de fila que outros sistemas de fila tem. Existe também o [kue](https://github.com/Automattic/kue), muito mais robusto porém, menos performático.
  ##### Instalando o Bee Queue
  > yarn add bee-queue
  Agora lá na pasta **lib** vou criar um arquivo **Queue.js** onde será configurado tudo relacionado a nossa fila.
  ```
    import Bee from 'bee-queue';

    class Queue {
      constructor() {
        // Aqui dentro poderei ter várias filas. Na verdade, cada tipo de serviço
        // terá sua própria fila.

        this.queues = {};

        this.init();
          // Dividir a parte de inicialização das filas em outro método.
      }

      init() {
        // Importaremos uma série de jobs, isso vem lá de background-jobs.
      }
    }

    export default new Queue();
  ```
  Criaremos uma pasta **jobs** dentro da pasta _app_, com um arquivo **CancellationMail.js**
  ```
    import { format, parseISO } from 'date-fns';
    import pt from 'date-fns/locale/pt';
    import Mail from '../../lib/Mail';

    class CancellationMail {
      get key() {
        return 'CancellationMail';
          // Retornarei uma chave única, dando a ela o mesmo nome da classe.
          // Para cada job precisamos de uma chave única.
      }

      // Então uma fila pode enviar 10 emails e o handle() será chamado para 
      // o envio de cada email.
      async handle({ data }) {
        // vou receber uma propriedade que será configurada posteriormente
        // e dentro deste objeto virá um 'data' que conterá todas as informações
        // que vão chegar ao nosso envio de emails

        const { appointment } = data;

        await Mail.sendMail({
          to: `${appointment.provider.name} <${appointment.provider.email}>`,
          subject: 'Agendamento cancelado',
          template: 'cancellation',
          context: {
            provider: appointment.provider.name,
            user: appointment.user.name,
            date: format(parseISO(appointment.date),
              "'dia' dd 'de' MMMM', às' H:mm'h'", 
              {
                locale: pt,
              }
            );
          },
        })
      }
    }

    export default new CancellationMail();
  ```
  Pronto, o nosso job de envio de emails está pronto! Agora no arquivo **Queue.js** iremos importar o **CancelationMail**.
  ```
    ....
    import CancellationMail from '../app/jobs/CancellarionMail';
    import redisConfig from '../config/redis';
      // Arquivo criado logo abaixo

    const jobs = [CancellationMail];

    class Queue {
      constructor() {
        this.queues = {};
        ....
      }
      
      init() {
        jobs.forEach(({ key, handle }) => {
          // Posso acessar o key e o handle com a desestruturação
          this.queues[key] = {
            bee: new Bee(key, {
              redis: redisConfig,
            }),
            handle,
              // Estamos pegando todos os jobs da aplicação e armazenando dentro
              // da variável this.queues. Dentro dela armazenamos a nossa fila (bee)
              // e armazenamos também o método handle (processa o job).
          }
        });
      }

      // primeiro parâmetro: qual fica quero adicionar o job
      // segundo  parâmetro: dados do job em si
      add(queue) {
        // Agora precisamos de um método que adiciona novas filas. Por exemplo,
        // cada vez que um email for disparado, preciso incluir este job dentro
        // da fila para ser processado.

        return this.queues[queue].bee.createJob(job).save();
          // Passo a queue como parâmetro em seguida utilizo o Bee para criar a Job
          // e salva-la no banco de dados.
      }

      // Agora toda vez que chamarmos o método add() passando cancellationMail como
      // primeiro parâmetro e os dados do appointments como segundo parâmetro, ele
      // irá incluir esse novo trabalho na fila.
    }

    // Até agora estamos inicializando as nossas filas, adicionando as jobs nas filas, 
    // porém ainda não estamos processando as filas. Criaremos então um novo método.
    processQueue() {
      // Vou percorrer cada um dos jobs, e para cada job receberei o job em si.
      jobs.forEach(job => {
        const { bee, handle } = this.queues[job.key];

        bee.process(handle);
      });
    }

  ```
  Na pasta config eu crio um novo arquivo **redis.js**
  ```
    export default {
      host: '127.0.0.1',
        // Por padrão o redis roda no mesmo host da aplicação
      port: 6379,
    }
  ```
Agora lá em AppointmentController vou importar a **fila** ao invés do **Mail**, e agora lá onde estavamos enviando o email, adicionaremos:
  ```
    ....
    import CancellationMail from '../jobs/CancellationMail';
    ....

    await Queue.add(CacellationMail.key, {
      appointment
    });
    ....
  ```
Para finalizar, na raiz do projeto criaremos um arquivo **queue.js**
```
  import Queue from './lib/Queue';

  Queue.processQueue();

```
  Mas por que criar este arquivo? Basicamente, porque não iremos executar a aplicação no mesmo node(na mesma execução) que iremos executar a fila. Porque podemos ter a fila rodando em um servidor, em um cor do processador, com mais ou menos recursos totalmente isolados da aplicação, assim a fila nunca irá influenciar na perfomace e no restante  da aplicação.

  Agora podemos ter um segundo terminal rodando a minha fila
  > node src/queue.js
  Caso esteja utilizando o sucrase, basta adicionar no **package.json** em **scripts** uma nova propriedade
  > "queue": "nodemon src/queue.js"
  e rodar o seguinte script no terminal:
  > yarn queue

## Monitorando falhas na fila
Lá no método **processQueue()** dentro de Queue.js da pasta _lib_ basta adicionar uma função para ouvir um evento.
  ```
    processQueue() {
      jobs.forEach( job => {
        ....

        bee.on('failed', this.handleFailure).process(handle);
          // Caso ocorra uma falha, ocorrerá uma chamada ao método handleFailure
      });
    }

    handleFailure(job, err) {
      console.log(`Queue ${job.queue.name}: FAILED`, err);
        // Printa no console o error com o nome da fila (key).
    }
  ```