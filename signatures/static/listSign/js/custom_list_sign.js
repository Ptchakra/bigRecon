function deleteSign(id)
{
    var delAPI = 'delete/' + id;
    swal.queue([{
        title: 'Are you sure you want to delete '+ id +'?',
        text: "You won't be able to revert this!",
        type: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Delete',
        padding: '2em',
        showLoaderOnConfirm: true,
        preConfirm: function() {
          return fetch(delAPI, {
	            method: 'DELETE',
                credentials: "same-origin",
                headers: {
                    "X-CSRFToken": getCookie("csrftoken")
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    swal.insertQueueStep({
                        type: 'success',
                        title: 'Deleted Successfully!'
                    })
                }
                else {
                    swal.insertQueueStep({
                        type: 'error',
                        title: 'Something went wrong!'
                    })
                }
            })
            .then(result => location.reload())
            .catch(function() {
              swal.insertQueueStep({
                type: 'error',
                title: 'Oops! Unable to delete'
              })
            })
        }
    }])
}

function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

function deleteAll() {
    swal.queue([{
        title: 'Are you sure you want to delete all signature?',
        text: "You won't be able to revert this!",
        type: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Delete',
        padding: '2em',
        showLoaderOnConfirm: true,
        preConfirm: function() {
          return fetch('deleteAll', {
	            method: 'DELETE',
                credentials: "same-origin",
                headers: {
                    "X-CSRFToken": getCookie("csrftoken")
                }
            })
            .then(response => response.json())
            .then(function (response) {
                if (response.success) {
                    swal.insertQueueStep({
                        type: 'success',
                        title: 'Deleted Successfully!'
                    })
                }
                else {
                    swal.insertQueueStep({
                        type: 'error',
                        title: 'Something went wrong!'
                    })
                }
            })
            .then(data => location.reload())
            .catch(function() {
              swal.insertQueueStep({
                type: 'error',
                title: 'Oops! Unable to delete'
              })
            })
        }
    }])
}

function reloadSign() {
    swal.queue([{
        title: 'This will delete all sign data and reload, do you want to continue?',
        text: "You won't be able to revert this!",
        type: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Reload',
        padding: '2em',
        showLoaderOnConfirm: true,
        preConfirm: function() {
          return fetch('reloadAll', {
	            method: 'POST',
                credentials: "same-origin",
                headers: {
                    "X-CSRFToken": getCookie("csrftoken")
                }
            })
            .then(response => response.json())
            .then(function (response) {
                swal.insertQueueStep({
                    type: 'info',
                    title: `Loaded ${response.numSignLoaded || 0} signature!` 
                })
                
            })
            .then(function(data) {
               return location.reload();
            })
            .catch(function() {
              swal.insertQueueStep({
                type: 'error',
                title: 'Oops! Unable to reload'
              })
            })
        }
    }])
}