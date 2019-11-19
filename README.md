# Docker
### Como funciona?
  O Docker serve para muitas coisas, como criação de ambientes isolados (container) que não vão interferir em outras ferramentas dentro do nosso servidor.

  Imagine uma necessidade de ter um banco de dados instalados como o Postgres, a instalação tradicional, mexerá em vários arquivos do  sistema, e se em algúm momento precisar excluir, alterar ou até mesmo atualizar, torna-se complicado. Porque esse banco de dados provavelmente mexeu em vários arquivos do sistema. 
  
  Então quando cria-se ambientes isolados com o Docker, aquele sistema fica totalmente desconexos de outros serviços da aplicação.

  Na instação do Postgres, ele ficará em um sub-sistema da máquina que não vai interferir no restante do sistema, o container jamais irá mexer em arquivos do restante da aplicação ou até do sistema operacional. E esses containers expões portas para comunicação.

### Principais conceitos
  - Imagem (seriço disponível do docker);
  - Container é uma instância de uma imagem;
  - Docker Registry (Docker Hub), onde fica todas as imagens do Docker;
  - Dockerfile (é a receita para criarmos nossa própria imagem);

###### Partimos de uma imagem existente
**FROM** node:10
###### Definimos a pasta e copiamos os arquivos
**WORKDIR** /usr/app
**COPY** . ./
###### Instalamos as dependências
**RUN** yarn
###### Qual porta queremos export?
**EXPOSE** 3333
###### Executamos nossa aplicação
**CMD** yarn start

### Instalação do Docker
Basta acessar em [Docker CE](https://docs.docker.com/install/) e seguis os 
passos para a instalação baseado ao sistema operacional.
##### Criando serviços de banco de dados [Postgres](https://hub.docker.com/_/postgres)
```
  docker run --name database -e POSTGRES_PASSWORD=docker -p 5432:5432 -d postgres:11
```
##### Principais comandos
```
  docker help
  docker ps
  docker ps -a
  docker start (dbName || id)
  docker stop  (dbName || id)
  docker rm    (dbName || id)
```

# Sequelize
O Sequelize é um ORM para NodeJS, para banco de dados relacionais.
### ORM
  - É uma forma de abstrair o banco de dados, mudando a forma como nosso banco de dados funciona e a forma como a nossa aplicação se comunica com o banco de dados.
  - As nossas tabelas viram models.
  > users     => User.js
  > companies => Company.js
  > projects  => Project.js
### Manipulação dos dados
  - Geralmente não será usada SQL, como:
    ```
      INSERT INTO users (name, email)
        VALUES (
          "Klinton Lee",
          "klintonlee@email.com.br"
        )
    ```
    ```
      SELECT *
        FROM users
       WHERE email = "klintonlee@email.com.br"
       LIMIT 1
    ```
  - Apenas código JavaScript:
    ```
      User.create({
        name: 'Klinton Lee',
        email: 'klintonlee@email.com.br"
      })
    ```
    ```
      User.findOne({
        where: {
          email: "klintonlee@email.com.br
        }
      })
    ```
  Eu escrevo os comandos usando apenas JavaScript e o Sequelize fará o papel de traduzir para código SQL.
### Migrations
  - Controle de versões para base de dados;
  - Cada arquivo contém instruções para criação, alteração ou remoção de tabelas ou colunas;
  - Mantém a base de dados atualizada entre todos os desenvolvedores do nosso time e também no ambiente de produção;
  - Cada arquivo é uma migração e sua ordenação ocorre por _data_ (vamos supor que crie uma migration para relacionar-se com uma tabela criada por uma migration posterior. Isso não pode ocorrer!)

###### Modelo de migration
  ```
    module.exports = {
      up: (queryInterface, Sequelize) => {
        return queryInterface.createTable('users', {   <--- Introdução para criar 
          id: {                                             nova tabela  
            allowNull: false,
            autoIncrement: true,      <-----
            primaryKey: true,                \
            type: Sequelize.INTEGER           \
          },                                   \
          name: {                               \ Criação de 3 campos com suas
            allowNull: false,          <--------- propriedades. O ID é a chave
            type: Sequelize.STRING              / **primária** e auto **incremental**
          },                                   / 
          email: {                            /
            allowNull: false,                /
            unique: true,             <-----
            type: Sequelize.STRING
          }
        })
      },
      down: (queryInterface, Sequelize) => {
        return queryInterface.dropTable('users')   <--- Instrução para deletar a
      }                                                 tabela casa haja um rollback
    }
  ```
Lembrando: A partir do momento que nossa migration foi para outros usuários, a gente nunca pode editar uma migration, é preciso criar uma nova migration adicionando um novo campo.

- É possível desfazer uma migração se errarmos algo enquanto estivermos desenvolvendo a feature. Basta dar um _rollback_, faço as alterações necessários e rodo a migration novamente;
- Depois que a migration foi enviada para outros devs ou para ambiente de produção, ela JAMAIS poderá ser alterada, uma nova deve ser criada;
- Cada migration deve realizar alterações em apenas uma tabela, pode-se criar várias migrations para alterações maiores;

### Seeds
  Muito útil para ambientes de testes.
  - População da base de dados para desenvolvimento (usuários fakes, produtos fakes, etc)
  - Muito utilizado para popular dados para testes;
  - Executável apenas por código;
  - Jamais será utilizado em produção;
  - Caso sejam dados que precisam ir para produção, a própria migration pode 
  manipular dados das tabelas;

# Arquitetura MVC
  ##### Model
  O model armazena a abstração do banco, utilizado para manipular os dados contidos nas tabelas do banco. Não possuem responsabilidades sobre a regra de negócio da nossa aplicação.
  ##### Controller
  O controller é o ponto de entrada das requisições da aplicação, uma rota geralmente está associada diretamente com um método do controller. Podemos incluir a grande parte das regras de negócio da aplicação nos controllers (conforme a aplicação cresce podemos isolar as regras).
  ##### View
  A view é o retorno ao cliente, em aplicações que sem o modelo API REST, pode ser um HTML, mas neste caso a view é apenas um JSON que será retornado ao front-end e depois manipulado pelo ReactJS ou React Native.
## A face de um controller
  - Ele basicamente é uma classe;
  - Sempre retorna um JSON;
  - Jamais vai chamar outro controller/ método;
  - _Quando criar um novo controller?_
      > Toda vez que a gente tem uma nova entidade

      > entidade não é a mesma coisa que model, mas geralmente cada model tem seu próprio controller

      > Mas pode ocorrer do controller não ter um model, exemplo: uma autenticação do usuário, não estou criando um novo usuário e sim uma sessão.

    > **Sempre vai ter apenas 5 métodos**
    ```
      class UserController {
        index()  { } // Listagem de usuários
        show()   { } // Exibir um único usuário
        store()  { } // Cadastrar usuário
        update() { } // Alterar usuário
        delete() { } // Remover usuário
      }
    ```

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