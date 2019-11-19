# Arquitetura MVC
  - **Model**: armazena a abstração do banco, utilizado para manipular os dados contidos nas tabelas do banco. Não possuem responsabilidades sobre a regra de negócio da aplicação.
  - **Controller**: é o ponto de entrada das requisições da aplicação, uma rota geralmente está associada diretamente com um método do controller. Podemos incluir a grande parte das regras de negócio da aplicação nos controllers (conforme a aplicação cresce podemos isolar as regras).
  - **View**: é o retorno ao cliente, em aplicações que sem o modelo API REST, pode ser um HTML. Em modelos API REST, um JSON será retornado para ser consumido pelo front-end.
## A face de um controller
  - Ele basicamente é uma classe;
  - Sempre retorna um JSON;
  - Jamais vai chamar outro controller/ método;
  - **Quando criar um novo controller?**
    > Toda vez que a gente tem uma nova entidade

    > entidade não é a mesma coisa que model, mas geralmente cada model tem seu próprio controller

    > Mas pode ocorrer do controller não ter um model, exemplo: uma autenticação do usuário, não estou criando um novo usuário e sim uma sessão.

  - **Sempre haverá estes 5 métodos, ou menos**
    ```
      class UserController {
        index()  { } // Listagem de usuários
        show()   { } // Exibir um único usuário
        store()  { } // Cadastrar usuário
        update() { } // Alterar usuário
        delete() { } // Remover usuário
      }
    ```