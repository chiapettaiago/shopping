document.addEventListener('DOMContentLoaded', function () {
    var socket = io();
    var notificationContainer = document.getElementById('notification-container');

    socket.on('notification', function (data) {
        var notification = document.createElement('div');
        notification.className = 'toast align-items-center text-white bg-primary border-0';
        notification.setAttribute('role', 'alert');
        notification.setAttribute('aria-live', 'assertive');
        notification.setAttribute('aria-atomic', 'true');

        notification.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    ${data.message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        `;

        notificationContainer.appendChild(notification);

        var toast = new bootstrap.Toast(notification);
        toast.show();

        // Remove a notificação após 5 segundos
        setTimeout(function () {
            toast.hide();
            setTimeout(function () {
                notificationContainer.removeChild(notification);
            }, 500);
        }, 5000);
    });
});
