// Obtém o HTML do gráfico gerado no Flask
var graph_html = "{{ graph_html|safe }}";
document.getElementById('chart').innerHTML = graph_html;