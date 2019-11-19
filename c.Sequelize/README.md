# Sequelize
O Sequelize é um **ORM**(Object-Relationa mapping) para NodeJS. Para quem não sente a vontade em escrever código SQL, o _ORM_ permite armazenar objetos no banco de dados.
  - As nossas tabelas viram models.
  > users     => User.js
  > companies => Company.js
  > projects  => Project.js
  - Eu escrevo os comandos usando apenas JavaScript e o Sequelize fará o papel de traduzir para código SQL.
#### Antes
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
#### Depois
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
  
## Migrations
  - Controle de versões para base de dados;
  - Cada arquivo contém instruções para criação, alteração ou remoção de tabelas ou colunas;
  - Mantém a base de dados atualizada entre todos os desenvolvedores do nosso time e também no ambiente de produção;
  - Cada arquivo é uma migração e sua ordenação ocorre por _data_ (vamos supor que crie uma migration para relacionar-se com uma tabela criada por uma migration posterior. Isso não pode ocorrer!)

### Modelo de migration
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
**Lembrando**:
-A partir do momento que nossa migration foi para outros usuários, nunca poderemos editar esta migration, é preciso criar uma nova migration adicionando um novo campo, por exemplo.
- É possível desfazer uma migração se errarmos algo enquanto estivermos desenvolvendo a feature. Basta dar um _rollback_, faço as alterações necessários e rodo a migration novamente;
- Cada migration deve realizar alterações em apenas uma tabela, pode-se criar várias migrations para alterações maiores;

### Seeds
  Muito útil para ambientes de testes:
  - População da base de dados para desenvolvimento (usuários fakes, produtos fakes, etc.)
  - Muito utilizado para popular dados para testes;
  - Executável apenas por código;
  - Jamais será utilizado em produção;
  - Caso sejam dados que precisam ir para produção, a própria migration pode manipular dados das tabelas;