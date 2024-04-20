var no_path = 0;
var no_headers = 0;
var no_detect = 0;
var no_conclusion = 0;
var no_condition = 0;
var no_generator = 0;
var no_payload = 0;
var no_var = 0;

$(document).ready(() => {
    $('.single-request').clone().show().appendTo($('.requests'));

    $(document).on('change', '#signtype', function () {
        var type = $(this).val();
        if (type == 'fuzz') {
            $.each($('.single-request'), function (index, value) { 
                $(this).find('.fuzz-signature').show();
                $(this).find('.list-signature').hide();
            });
        }
        else {
            $.each($('.single-request'), function (index, value) { 
                $(this).find('.list-signature').show();
                $(this).find('.fuzz-signature').hide();
            });  
        }
    });

    $(document).on('click', '#add-condition-btn', function () {
        var cur = $(this).closest('.signature-conditions');
        cur.find('#clone-condition-0').clone().show().prop('id', 'clone-condition-' + no_condition).appendTo(cur);
        no_condition++;
    });

    $(document).on('click', '#delete-condition-btn', function () {
        $(this).closest('.condition-group').remove();
    });

    $(document).on('click', '#add-path-btn', function () {
        var cur = $(this).closest('.signature-paths');
        cur.find('#clone-path-0').clone().show().prop('id', 'clone-path-' + no_path).appendTo(cur);
        no_path++;
    });

    $(document).on('click', '#delete-path-btn', function () {
        $(this).closest('.path-group').remove();
    });

    // $('#add-path-btn').click(() => {
    //     $(this).closest('.path-group').find('#clone-path-0').clone().show().prop('id', 'clone-path-' + no_path).appendTo($('.signature-paths'));
    //     no_path++;
    // });

    $('#add-request-btn').click(() => {
        $('.single-request:first').clone().show().appendTo($('.requests'));
    });

    $(document).on('click', '#add-header-btn', function () {
        var cur = $(this).closest('.signature-headers');
        cur.find('#clone-path-0').clone().show().prop('id', 'clone-header-' + no_headers).appendTo(cur);
        no_headers++;
    });

    $(document).on('click', '#delete-header-btn', function () {
        $(this).closest('.headers-group').remove();
    });

    // $('#add-header-btn').click(() => {
    //     $('#clone-header-0').clone().show().prop('id', 'clone-header-' + no_headers).appendTo($('.signature-headers'));
    //     no_headers++;
    // });

    $(document).on('click', '#add-detect-btn', function () {
        var cur = $(this).closest('.signature-detects');
        cur.find('#clone-detect-0').clone().show().prop('id', 'clone-detect-' + no_detect).appendTo(cur);
        no_detect++;
    });

    // $('#add-detect-btn').click(() => {
    //     $('#clone-detect-0').clone().show().prop('id', 'clone-detect-' + no_detect).appendTo($('.signature-detects'));
    //     no_detect++;
    // });

    $(document).on('click', '#delete-detect-btn', function () {
        $(this).closest('.detect-group').remove();
    });

    $(document).on('click', '#add-conclusion-btn', function () {
        var cur = $(this).closest('.signature-conclusions');
        cur.find('#clone-conclusion-0').clone().show().prop('id', 'clone-conclusion-' + no_conclusion).appendTo(cur);
        no_conclusion++;
    });

    $(document).on('click', '#delete-conclusion-btn', function () {
        $(this).closest('.conclusion-group').remove();
    });

    // $('#add-conclusion-btn').click(() => {
    //     $('#clone-conclusion-0').clone().show().prop('id', 'clone-conclusion-' + no_conclusion).appendTo($('.signature-conclusions'));
    //     no_conclusion++;
    // });

    $(document).on('click', '#add-gen-btn', function () {
        var cur = $(this).closest('.signature-generators');
        cur.find('#clone-gen-0').clone().show().prop('id', 'clone-gen-' + no_generator).appendTo(cur);
        no_generator++;
    });

    // $('#add-gen-btn').click(() => {
    //     $(this).closest('.signature-generators').find('#clone-gen-0').clone().show().prop('id', 'clone-gen-' + no_generator).appendTo($('.signature-generators'));
    //     no_generator++;
    // });

    $(document).on('click', '#delete-gen-btn', function () {
        $(this).closest('.gen-group').remove();
    });

    $('#add-payload-btn').click(() => {
        $('#clone-payload-0').clone().show().prop('id', 'clone-gen-' + no_payload).appendTo($('.payloads'));
        no_payload++;
    });

    $(document).on('click', '#delete-payload-btn', function () {
        $(this).closest('.payload-group').remove();
    });

    $(document).on('change', '#payload-input-file', function () {
        var fr = new FileReader();
        fr.onload = function() {
            $('#payload-text').val(fr.result);
        }
        fr.readAsText(this.files[0]);
    });

    $('#add-variable-btn').click(() => {
        $('#clone-variable-0').clone().show().prop('id', 'clone-variable-' + no_var).appendTo($('.variables'));
        no_var++;
    });

    $(document).on('click', '#delete-variable-btn', function () {
        $(this).closest('.variable-group').remove();
    });

    $(document).on('click', '#generate-btn', function generateYAML() {
        let yaml_data = {};
        yaml_data['id'] = $('#signid').val();
        let type = $('#signtype').val();
        if (!!type) yaml_data['type'] = type;
        let donce = $('#donce').prop('checked');
        if (donce) yaml_data['donce'] = true;

        let info = {};
        let name = $('#signname').val();
        if (!!name) info['name'] = name;
        let risk = $('#signrisk').val();
        if (!!risk) info['risk'] = risk;
        let conf = $('#signconf').val();
        if (!!conf) info['confidence'] = conf;
        let os = $('#signos').val();
        if (!!os) info['os'] = os;
        let tech = $('#signtech').val();
        if (!!tech) info['tech'] = tech;
        if (Object.keys(info).length) yaml_data['info'] = info;

        let payload = $('.signpayload').val();
        let payload_arr = payload.split('\n');
        payload_arr = payload_arr.map(item => item.trim());
        payload_arr = payload_arr.filter(x => !!x);
        if (payload_arr.length) yaml_data['payloads'] = payload_arr;

        let variables = [];
        $.each($('.variable-group'), function (index, value) { 
            let var_name = $(this).find('.name').val();
            let var_value = $(this).find('.value').val();
            if (!!var_name && !!var_value) {
                variables.push({ [var_name]: var_value })
            }
        });
        if (variables.length) yaml_data['variables'] = variables;

        let requests = [];
        $.each($('.single-request'), function (index, value) {
            let request = {};
            let conditions = [];
            $.each($(this).find('.signcondition'), function (index, value) { 
                let val = $(this).val();
                if ($(this).is(':visible') && val) conditions.push(val);
            }); 
            if (conditions.length) request['conditions'] = conditions;

            let redirect = $(this).find('#redirect').prop('checked');
            if (redirect) request['redirect'] = true;

            if ($('#signtype').val() == 'fuzz') {
                $.each($(this).find(".signgen"), function (index, value) { 
                    let gen = $(this).val().trim();
                    if (!!gen) path_arr.push(gen);
                });
            }
            else {
                let raw = $(this).find('#signraw').prop('checked');
                if (raw) yaml_data['raw'] = $('#raw-request').val();
                else {
                    let method = $(this).find('#signmethod').val();
                    if (!!method) request['method'] = method;
                    else return;
    
                    let path = $(this).find('.signpath').val();
                    path = path.trim();
                    if (!!path) request['url'] = path;
        
                    let headers = [];
                    $.each($(this).find(".headers-group"), function (index) {
                        let field_name = $(this).find('.key').val();
                        let value = $(this).find('.value').val();
                        if (!!field_name && !!value) {
                            headers.push({ [field_name]: value })
                        }
                    });
                    if (headers.length) request['headers'] = headers;

                    let body = $(this).find('.body-content').val();
                    body = body.trim();
                    if (!!body) request['body'] = body;
                }
            }

            let detections = [];
            $.each($(this).find(".detect-group"), function (index) {
                let exp_arr = [];
                let status = $(this).find('.detect-status').val();
                if (status) exp_arr.push('StatusCode() == ' + status);
                let search_str = $(this).find('.detect-string').val();
                if (search_str) {
                    search_str.split(', ').map(item => {
                        if (item) exp_arr.push('StringSearch("response", "'.concat(item, '")'));
                    });
                }
                let custom = $(this).find('.custom-detect').val();
                if (custom) {
                    let custom_arr = custom.split(', ');
                    if (custom_arr.length) exp_arr = exp_arr.concat(custom_arr);
                }
                if (exp_arr.length) detections.push(exp_arr.join(' && '));
            });
            if (detections.length) request['detections'] = detections;
            else alert('Please input detection part!');

            let conclusions = [];
            $.each($(this).find('.signconclusion'), function (index, value) { 
                let val = $(this).val();
                if ($(this).is(':visible') && val) conclusions.push(val);
            }); 
            if (conclusions.length) request['conclusions'] = conclusions;

            let middleware = $(this).find('.signmid').val().trim();
            if (middleware) request['middleware']= middleware;
            console.log(request);

            if (Object.keys(request).length) requests.push(request);
        });
        
        yaml_data['requests'] = requests;
        
        console.log(yaml_data);
        sendJson(yaml_data);
    });
    
    function sendJson(data) {
        var formData = {
            data: JSON.stringify(data)
        }

        $.ajax({
            type: "POST",
            headers: {
                "X-CSRFToken": getCookie("csrftoken")
            },
            data: formData,
            dataType: "json",
            success: function (response) {
                if (response.success) {
                    swal({
                        title: '',
                        text: 'Added successfully!',
                        type: 'success'
                    });
                    let cols = $('textarea#raw-input').prop('cols');
                    let text = response.gen_sign;
                    let linecount = 0;
                    text.split("\n").map(function(l) {
                        linecount += 1 + Math.floor(l.length / cols); 
                    });
                    $('textarea#raw-input').prop('rows', linecount);
                    $('textarea#raw-input').val(text);
                }
                else {
                    swal({
                        title: '',
                        text: 'Cannot add. Please check and try again!',
                        type: 'error'
                    });
                }
            }
        });
    }
});

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

function changeState(checkbox) {
    if (checkbox.checked) {
        $('#raw-input').prop('disabled', false);
        $('#submit-raw-btn').removeClass('d-none');
    }
    else {
        $('#raw-input').prop('disabled', true);
        $('#submit-raw-btn').addClass('d-none');
    }
}

function changeHttpRawState(checkbox) {
    if (checkbox.checked) {
        $(checkbox).parent().siblings('#raw-request').show();
        $(checkbox).parent().siblings('#manual-request').hide();
    } else {
        $(checkbox).parent().siblings('#raw-request').hide();
        $(checkbox).parent().siblings('#manual-request').show();
    }
}

function submitRawSignature() {
    let raw_data = document.getElementById("raw-input").value;
    var formData = {
        raw: raw_data
    }

    $.ajax({
        type: "POST",
        headers: {
            "X-CSRFToken": getCookie("csrftoken")
        },
        data: formData,
        dataType: "json",
        success: function (response) {
            if (response.success) {
                swal({
                    title: '',
                    text: 'Added successfully!',
                    type: 'success'
                });
            }
            else {
                swal({
                    title: '',
                    text: 'Cannot add. Please check and try again!',
                    type: 'error'
                });
            }
        }
    })
}


