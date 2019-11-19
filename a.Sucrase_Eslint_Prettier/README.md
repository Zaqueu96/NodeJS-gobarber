# Configuração do ambiente em NodeJS
Atualmente, o Node ainda utiliza a sintaxe do _CommonJS_:
```
  var express = require('express');
  var app = express();
  ....
  module.exports = app;
```
### Sucrase + Nodemon
Permite utilizar as funcionalidades mais recentes como o **"import/export"**. Além de ser extremamente rápido. O **Nodemon** permite utilizar o live reload.
```
  import express from 'express';
  var app = express();
  ....
  export default app;
```
> Instalando o Sucrase + Nodemon
```
  yarn add sucrase nodemon -D
```
> Como usar o Sucrase?
Basta utilizar o **sucrase-node** antes do arquivo principal:
```
  yarn sucrase-node src/serve.js
```
### Integrando Nodemon com Sucrase
Ao inicializar o projeto, precisaremos acessar o _package.json_ e criar um script:
```
  ....
  "scripts": {
    "dev": "nodemon src/server.js"
  }
  ....
```
Em seguida, crie um arquivo *nodemon.json* na raíz do projeto com o seguinte código:
```
  {
    "execMap": {
      "js": "sucrase-node"
    }
  }
```
Essa configuração executará o 'sucrase-node' em todo arquivo '.js'.


# Padronização do código
Auxilia em futuras manutenções e no desenvolvimento do projeto entre todos os devs.

## Eslint
O eslint verifica se estamos seguindo os nossos padrões, além de corrigi-los.
> Instalando o eslint
```
  yarn add eslint -D
```
> Feito a instalação, iniciaremos as configuração:
```
  yarn eslint --init
```
  1. How would you like to use Eslint?

    - To check syntax, find problems, and enforce code style

  2. What type of module does your project use?

    - JavaScript modules (impor/export)

  3. Which framework does your project use?

    - None of these

  4. Does your project use TypeScript? (y/N)

    - N (Enter)

  5. Where does your code run?

    - Node (desselecionar, Browser e selecionar Node)

  6. How would you like to define a style for your project?

    - Use a popular style guide

    - Airbnb

  7. What format do you want your config file to be in?

    - JavaScript
> Would your like to install them now with npm?
  - Y (Enter)

Após a instalação, um arquivo **.eslintrc.js** será gerado na raíz do projeto. Caso esteja utilizando o yarn como package manager, basta excluir o arquivo _package-lock.json_ e executar o **yarn** que irá baixar novamente como _yarn.lock_.

### Configurando eslint
Será necessário instalar uma extensão no VSCode responsável por mostrar os erros que estão fora do padrão, o ESLint (Dirk Baeumer).

É possível configurar um **fix automático**. Nas configurações do VSCode, _Ctrl + Shift + P_, em Preferences: Open Settings (JSON) eu preciso ter as seguintes propriedades configuradas:
```
  "eslint.autoFixOnSave": true,
  "eslint.validate" : [
    {
      "language": "javascript",
      "autoFix": true
    },
    {
      "language": "javascriptreact",
      "autoFix": true
    },
    {
      "language": "typescript",
      "autoFix": true
    },
    {
      "language": "typescriptreact",
      "autoFix": true
    },
  ]
```

### Sobrescrevendo algumas regras do Eslint
```
  rules: {
    "class-methods-use-this": "off",
      // Toda classe deve utilizar o 'this'
    "no-param-reassign": "off",
      // não permite receber um parâmetro e altera-lo
    "camelcase": "off",
      // todas variáveis devem ser em camelCase
    "no-unused-vars": ["error", { "argsIgnorePattern": "next" }],
      // não permite utilizar variáveis que não serão utilizadas
  },
```

### Prettier
Essa ferramenta deixa o nosso código mais bonito.
> Instalação do Prettier
```
  yarn add prettier eslint-config-prettier eslint-plugin-prettier -D
```
> Em seguida precisaremos acrescentar nas **rules** do **eslint** uma nova regra:
```
  rules: {
    "prettier/prettier": "error",
    . . .
  }
  
```
> Adicionar a extensão e o plugin (faz a integração do prettier + eslint)
```
  extends: [
    'airbnb-base',
    'prettier'
  ],
  plugins: [ 'prettier' ],
```
Algumas configurações do _prettier_ são diferentes do _airbnb_, por isso precisaremos criar um arquivo **.prettierrc** para sobreescrever algumas regras.
```
  {
    "singleQuote": true,
      // aspas simples
    "trailingComma": "es5"
      // vírgula no final de objetos e arrays
  }
```