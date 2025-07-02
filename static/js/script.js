async function testLogin() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const resultDiv = document.getElementById('result');
    const loadingDiv = document.getElementById('loading');

    // Clear previous results and show loading
    resultDiv.innerHTML = '';
    loadingDiv.classList.remove('d-none');

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        // Hide loading
        loadingDiv.classList.add('d-none');

        if (response.status === 429) {
            // Handle rate limit exceeded
            resultDiv.innerHTML = `
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    ${data.message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            `;
            return;
        }

        if (data.blocked) {
            resultDiv.innerHTML = `
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    ${data.message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            `;
        } else if (data.valid) {
            window.location.href = data.redirect;
        } else {
            resultDiv.innerHTML = `
                <div class="alert alert-warning alert-dismissible fade show" role="alert">
                    ${data.message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            `;
        }
    } catch (error) {
        loadingDiv.classList.add('d-none');
        resultDiv.innerHTML = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                Error: Unable to connect to the server.
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
    }
}