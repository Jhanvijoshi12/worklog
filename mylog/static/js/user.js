// ajax call for register, if any error is occurred
$('#register_btn').click(function(e) {
    e.preventDefault();
    csr = $('input[name="csrfmiddlewaretoken"]').val();
    register = $('#register_form').serializeArray();
    username = register.at(1).value;
    first_name = register.at(2).value;
    last_name = register.at(3).value;
    email = register.at(4).value;
    password = register.at(5).value;
    data = {'username': username, 'first_name': first_name, 'last_name': last_name,
           'email': email, 'password': password, 'csrfmiddlewaretoken': csr}
    $.ajax({
    type: "POST",
    url: "",
    data: data,
    dataType: 'json',
    success: function(response) {
             if (response.status === 'success') {
                alertify.set('notifier', 'position', 'top-right');
                alertify.success("User Register Successfully!!")
            }
            else {
             $('.alert-success').removeClass('msg-success-show');
              for (let key in response.errors) {
                   let error_message = response.errors[key];
                        alertify.set('notifier', 'position', 'top-right');
                        alertify.error(error_message)
                }
    };
    }
   });
   });


// function for error message
function handleError() {
    alertify.set('notifier', 'position', 'top-right');
    alertify.error("Please enter valid details to Register!!");
}


// function for daily log form error message
function validate() {
    csr = $('input[name="csrfmiddlewaretoken"]').val();
    log_form = $('#logForm').serializeArray();
    project = log_form.at(1).value;
    date = log_form.at(2).value;
    task = log_form.at(3).value;
    description = log_form.at(4).value;
    start_time = log_form.at(5).value;
    end_time = log_form.at(6).value;
    data = {'project_name': project, 'date': date, 'task': task,
           'description': description, 'start_time': start_time, 'end_time': end_time,
           'csrfmiddlewaretoken': csr}

    $.ajax({
    type: "POST",
    url: "{% url 'mylog:daily_log' %}",
    data: data,
    dataType: 'json',
    success: function(data){
        if (data.status === 201) {
            alertify.set('notifier', 'position', 'top-right');
            alertify.success("User Daily Log created Successfully!!")
        }
        else if (data.status === 400) {
            alertify.set('notifier', 'position', 'top-right');
            alertify.error(data.message)
        };
    }

   });
}

function addTask(id) {
    if (id) {
        tr_id = '#user-'+id;
        $('#addTaskModal').modal('show');
        $('#form-user').val(id);
    }
    else { return false }
}

// function when you save the manually created log
function saveDailyLog() {
    csr = $('input[name="csrfmiddlewaretoken"]').val();
    user_id = parseInt($('#form-user').val());
    project_name = $('#form-project').val();
    date_id = $('#form-date').val();
    task_name = $('#task-name').val();
    description_id = $('#description-text').val();
    start_time_id = $('#start-time').val();
    end_time_id = $('#end-time').val();

    $.ajax({
        type: 'post',
        url: '/add/log/',
        data: {'user': user_id, 'project_name': project_name, 'date': date_id, 'task': task_name,
        'description': description_id, 'start_time': start_time_id, 'end_time': end_time_id, 'csrfmiddlewaretoken': csr},
        dataType: 'json',
        success: function(data){
            if (data.status === 201) {
                alertify.set('notifier', 'position', 'top-right');
                alertify.success(data.message);
                $('#addTaskModal').modal('hide');
            }
            else if (data.status === 400) {
                alertify.set('notifier', 'position', 'top-right');
                alertify.error(data.message);
                $('#addTaskModal').modal('hide');
            }
        }
});
}

// function for creating project by ajax call
function createProject(){
    csr = $('input[name="csrfmiddlewaretoken"]').val();
    project_name = $('#id_project').val();

    $.ajax({
        type: 'post',
        data: {'name': project_name, 'csrfmiddlewaretoken': csr},
        url: '/create/project/',
        dataType: 'json',
        success: function(data){
                alertify.set('notifier', 'position', 'top-right');
                alertify.success('Project is created successfully!!');
                $('#projectModal').modal('hide');
        }
    });

}

// function for creating task by ajax call
function createTask(){
    csr = $('input[name="csrfmiddlewaretoken"]').val();
    task_form = $('#task-form').serializeArray();
    project_name_val = parseInt(task_form.at(1).value);
    title = task_form.at(2).value;

    $.ajax({
        type: 'post',
        data: {'project': project_name_val, 'title': title, 'csrfmiddlewaretoken': csr},
        url: '/create/task/',
        dataType: 'json',
        success: function(data){
                alertify.set('notifier', 'position', 'top-right');
                alertify.success('Task is created successfully!!');
                $('#taskModal').modal('hide');
        }
    });

}

// for opening datetimepicker onclick of date field filter
$('#id_filter_date').datepicker({
    format:'yyyy-mm-dd',
    autoclose: true,
    useCurrent: false,
    widgetPositioning: {
        horizontal: 'auto',
        vertical: 'bottom'
    }
});

// clear all filter fields when you click on clear filter button
$('.clear-filter').click(function (){
    clearFilter();
});

function clearFilter(){
    // if any filter is applied then it will clear all filters and search query parameters
    // and reload the page
    window.location.href = window.location.href.split("?")[0];
}

// function for  getting tasks related to selected project
document.getElementById("id_project_name").addEventListener("change", get_related_tasks);

function get_related_tasks() {
    project_id = document.getElementById("id_project_name").value;
    task_select = document.getElementById("id_task");
    task_select.innerHTML = "";
    $.ajax({
        url: '/get_related_tasks/',
        type: 'GET',
        data: {'project_id': project_id},
        dataType: 'json',
        success: function(data) {
            data.forEach(function (task) {
                option = document.createElement("option");
                option.value = task.id;
                option.text = task.title;
                task_select.appendChild(option);
            });
        }
    });
}

// for setting id of the task field from template
document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("id_task").addEventListener("change", setTaskId);

function setTaskId() {
    task_id = document.getElementById("id_task").value;
    $.ajax({
        url: '/get_task_details/',
        type: 'GET',
        data: {'task_id': task_id},
        success: function(data) {
            data.forEach(function (task) {
                option = document.createElement("option");
                option.value = task.id;
                option.text = task.title;
                document.getElementById('id_task').appendChild(option);
            });
        }
    });
}
});

// function is called when you click on create_csv button
function downloadcsv(){
    document.getElementById('create_csv').value='True';
    btn = $('#create_csv').val();
    if (btn === 'True') {
        alertify.set('notifier', 'position', 'top-right');
        alertify.success("CSV file is created successfully!!");
    }
}