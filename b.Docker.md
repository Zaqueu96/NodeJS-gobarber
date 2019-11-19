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