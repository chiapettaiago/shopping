// Função para definir o tema inicial antes da renderização da página
(function() {
    const storedTheme = localStorage.getItem('theme'); // Obtém o tema armazenado no localStorage
    const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)').matches; // Verifica se o sistema prefere o tema escuro

    // Aplica o tema armazenado ou o padrão do sistema antes de carregar a página
    if (storedTheme) {
        document.documentElement.setAttribute('data-bs-theme', storedTheme);
    } else {
        document.documentElement.setAttribute('data-bs-theme', prefersDarkScheme ? 'dark' : 'light');
    }
})();