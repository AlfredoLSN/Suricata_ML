## Ideia geral

A ferramenta funciona como um pipeline de monitoramento e inferência. Ela parte do tráfego real que passa por uma interface de rede, registra esse tráfego em capturas brutas, transforma essas capturas em fluxos de rede e, por fim, classifica cada fluxo com um modelo de Machine Learning.

Em alto nível, o processo pode ser entendido assim:

```text
tráfego de rede
    -> captura bruta dos pacotes
    -> extração de fluxos
    -> organização dos atributos dos fluxos
    -> classificação com modelo de Machine Learning
    -> geração dos resultados classificados
    -> alerta IDS via Telegram, quando houver fluxo suspeito
```

Cada etapa tem uma responsabilidade bem definida. A captura não precisa entender o significado dos dados, a extração não precisa decidir a classe do tráfego, e a classificação trabalha sobre dados já organizados em formato adequado para o modelo.

Atualmente a ferramenta opera somente em modo IDS. Isso significa que ela detecta e alerta sobre tráfego suspeito, mas não altera regras de firewall nem bloqueia IPs automaticamente.

## Captura do tráfego

A primeira camada da arquitetura é responsável por observar a interface de rede e registrar os pacotes que passam por ela.

Essa etapa trabalha com o tráfego em sua forma mais bruta. Ela não tenta interpretar se uma conexão é normal ou suspeita, nem aplica regras de decisão. Sua função é manter um registro contínuo do que está acontecendo na rede.

Para facilitar o processamento, a captura é dividida em blocos menores. Em vez de manter uma captura única e crescente, o sistema gera capturas separadas por intervalo de tempo. Isso permite que as próximas etapas processem partes menores do tráfego enquanto a captura continua acontecendo.

Essa separação é importante porque cria um fluxo contínuo: enquanto novos pacotes continuam sendo registrados, capturas já finalizadas podem seguir para transformação e análise.

## Extração de fluxos

A segunda camada transforma as capturas brutas em fluxos de rede.

Um fluxo representa uma comunicação agregada entre pontos da rede, reunindo informações como duração, quantidade de pacotes, volume de bytes, direção do tráfego e estatísticas temporais. Essa representação é mais adequada para Machine Learning do que os pacotes individuais, porque resume o comportamento de uma comunicação em um conjunto de atributos.

Essa etapa funciona como uma ponte entre o tráfego bruto e o modelo. Ela recebe capturas finalizadas, extrai características relevantes e produz uma estrutura tabular, onde cada linha representa um fluxo e cada coluna representa uma característica daquele fluxo.

O serviço de extração acompanha a chegada de novas capturas finalizadas. Quando uma captura fica pronta, ela entra em uma fila de processamento. Essa fila organiza o trabalho e permite que a extração aconteça de forma contínua, sem interromper a captura de novos pacotes.

## Classificação dos fluxos

A terceira camada aplica o modelo de Machine Learning sobre os fluxos extraídos.

Nessa etapa, os dados já estão em formato tabular. O classificador recebe os atributos de cada fluxo, organiza essas informações no formato esperado pelo modelo e executa a predição.

O resultado da classificação indica a classe atribuída a cada fluxo. Dependendo do modelo disponível, o resultado também pode trazer uma medida de confiança da predição.

Essa camada representa a parte de inferência da arquitetura. Ela não participa da captura dos pacotes nem da extração inicial das características; seu papel é interpretar os fluxos já estruturados e produzir uma saída classificada.

Antes da inferência, existe uma etapa de adaptação dos dados. Ela ajusta os nomes e a ordem das características para que os fluxos extraídos sejam compatíveis com o formato usado no treinamento do modelo. Essa adaptação evita que diferenças pequenas entre a saída do extrator e as colunas esperadas pelo modelo comprometam a predição.

Também existe uma etapa de filtragem de ruído. Ela permite remover da análise fluxos originados por endereços conhecidos, como o próprio host de captura, gateways ou máquinas internas que não devem gerar alerta. Essa filtragem acontece antes da classificação para que esses fluxos não influenciem nem os resultados classificados nem as notificações.

O resultado da classificação é persistido como uma nova visão dos fluxos: os atributos estruturados são mantidos junto com a predição do modelo, o rótulo interpretável da classe e, quando disponível, a confiança da decisão.

## Alerta IDS via Telegram

Depois da classificação, o sistema pode enviar alertas IDS pelo Telegram.

Essa etapa não bloqueia tráfego. Ela apenas observa a saída do classificador e avisa quando existem fluxos classificados fora do conjunto considerado benigno. Por isso, ela funciona como uma camada de notificação e acompanhamento, não como uma camada de contenção.

O alerta é construído a partir dos fluxos suspeitos encontrados em cada lote classificado. A mensagem apresenta os principais dados de comunicação do fluxo, como origem, destino, portas, protocolo, classe prevista e confiança quando disponível.

Como um mesmo lote pode conter muitos fluxos suspeitos, o envio é preparado para preservar a informação sem truncar a lista. Quando o alerta fica grande demais para uma única mensagem, ele é dividido em partes. Se houver uma falha temporária no envio, a camada de notificação tenta reenviar antes de desistir daquele alerta.

## Integração entre as camadas

As camadas trabalham de forma encadeada, mas com responsabilidades separadas.

A captura produz blocos de tráfego bruto. A extração percebe quando um bloco está pronto e o transforma em fluxos. A classificação recebe esses fluxos e gera as predições finais.

O desenho geral é:

```text
captura
    gera blocos de tráfego bruto

extração
    transforma capturas em fluxos estruturados

classificação
    aplica o modelo sobre os fluxos
    produz resultados classificados

resposta IDS
    identifica fluxos não benignos
    envia alerta no Telegram
```

Essa organização deixa a ferramenta modular. Cada etapa pode evoluir sem exigir que as outras assumam responsabilidades que não pertencem a ela. A captura continua focada em registrar tráfego, a extração continua focada em transformar dados brutos em atributos, e a classificação continua focada em aplicar o modelo.

## Comportamento operacional

Durante a execução, a ferramenta opera como um fluxo contínuo.

Enquanto a rede gera tráfego, a camada de captura registra os pacotes em blocos. Assim que um bloco de captura é finalizado, ele passa a ser tratado como uma unidade de trabalho pela camada de extração. Depois de convertido em fluxos, esse conjunto de dados segue para a camada de classificação.

Esse funcionamento permite que o sistema trabalhe de maneira incremental. A ferramenta não precisa esperar uma captura grande terminar para só então começar a análise. Em vez disso, cada bloco finalizado pode seguir pelo pipeline enquanto novos blocos continuam sendo produzidos.

Na prática, esse comportamento acontece por meio de processos complementares: um responsável por produzir as capturas e outro responsável por consumir capturas finalizadas, extrair fluxos, classificar e acionar a notificação IDS quando necessário.

## Resultado final

O resultado final da arquitetura é um conjunto de registros classificados.

Cada registro representa um fluxo de rede observado, acompanhado dos atributos extraídos e da classe prevista pelo modelo. Esses resultados permitem analisar o comportamento do tráfego capturado e identificar como o modelo classificou cada comunicação.

Além dos CSVs classificados, quando o modo IDS está ativo, o sistema também produz alertas no Telegram para os fluxos suspeitos. Esses alertas funcionam como uma camada de notificação operacional, permitindo acompanhar detecções sem abrir manualmente cada arquivo gerado.

Em resumo, a arquitetura transforma tráfego real em dados estruturados e classificados. Ela faz isso por meio de quatro responsabilidades principais: capturar pacotes, extrair fluxos, aplicar inferência com Machine Learning e emitir alertas IDS quando há tráfego suspeito.
