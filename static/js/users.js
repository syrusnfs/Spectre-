// users.js - User management

function deleteUser(userId) {
    showConfirmModal(
        'Delete User',
        'Are you sure you want to remove this user? All associated servers and routines will also be removed. This action cannot be undone.',
        function() {
            // Request OTP before executing
            requireOTP(function() {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = '/users/delete/' + userId;
                document.body.appendChild(form);
                form.submit();
            });
        }
    );
}
