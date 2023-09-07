1. Criar um par de chaves RSA local
2. Criar um post com um conteúdo que é uma cópia do `jwks.json`, mas trocando a chave pública pela criada no passo 1.
2.1 Anotar a URL desse post
3. Mandar um request pro cache, para o Desync

3.1 Precisa ser um POST por causa do `Content-Length`, então esse request pode ser um segundo post aleatório.
3.2 O `Content-Length` vai ser um tamanho onde vai o conteúdo de 3.1 e mais um outro request HTTP no final
3.3 O `Transfer-Encoding` deve ser `chunked`. Para efeito de chunked, ele termina efetivamente no final do conteúdo do POST aleatório (3.1)
3.4 Com isso, o Cache vai usar o `Content-Length` e entender que está mandando apenas um request, mas o nginx deve usar o `Transfer-Encoding` entender que está recebendo 2.

Tô pensando no resto ainda :D 