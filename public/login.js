
const form = document.getElementById('login');
const button = document.getElementById('submit');
const error = document.getElementById('error');

form.addEventListener('submit', async event => {
  event.preventDefault();

  error.textContent = '';
  button.disabled = true;
  button.textContent = 'ĐANG KIỂM TRA...';

  const data = new FormData(form);

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        username: data.get('username'),
        password: data.get('password')
      })
    });

    const result = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(result.error || 'Không thể đăng nhập');
    }

    location.replace('/index.html');

  } catch (e) {
    error.textContent = e.message;
  } finally {
    button.disabled = false;
    button.textContent = 'ĐĂNG NHẬP';
  }
});
