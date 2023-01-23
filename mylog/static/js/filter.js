var EMPTY_VALUES = [null , '', undefined, false]

$(document).ready(function () {
debugger;
    var filterList = ['user', 'date'];
    setFilterValues(filterList);
    $('a.page-link').click(function () {
        setHrefToPagination(this, filterList);
    });

    $('.clear-filter').click(function () {
        clearFilter();
    });
});

function setFilterValues(filterList) {
    // bind filter fields with their input field
    // if filter is applied
    debugger;
    showFilterList(filterList);
    $(filterList).each(function(index, fieldId){
        var field = $('#id_' + fieldId);
        if (field.is('select')){
            setSelectValues(field, GetURLParameter(fieldId));
        }
        else {
            setInputValue(field, GetURLParameter(fieldId));
        }
    });
    setInputValue($('input#id_search_name'), GetURLParameter('search_name'));
}

function setSelectValues(field, value){
    // set value to input field
    if (!EMPTY_VALUES.includes(value)){
        field.find('option[value="' + value + '"]').prop('selected', true);
    }
}

function setInputValue(field, value){
    // set value to input field
    if (!EMPTY_VALUES.includes(value)){
        field.val(value);
    }
}

function showFilterList(filterList){
    // if any filter is applied then show the filter list
    debugger;
    var parameterList = GetParameterValueList(filterList);
    if (! $.isEmptyObject(parameterList)){
        $(".filter-list").addClass('show');
    }
}

function GetParameterValueList(list){
    debugger;
    var parameterList = [];
    $.each(list, function(index, value){
        parameterList.push(GetURLParameter(value));
    });
    return removeDuplicate(parameterList);
}

function removeDuplicate(list){
    return list.filter(function(value){if (value!=='' || value!==undefined){return value}});
}


function GetURLParameter(sParam){
 // this function is for get value from url
    var sPageURL = window.location.search.substring(1);
    var sURLVariables = sPageURL.split('&');
    for (var i = 0; i< sURLVariables.length; i++){
        var sParameterName = sURLVariables[i].split('=');
        if (sParameterName[0] == sParam){
            return decodeURIComponent(sParameterName[1].replace(/\+/g, ' ').replace(/ +/g, ' '));
        }
    }

}

function clearFilter(){
    // if any filter is applied then it will clear all filters and search query parameters
    // and reload the page
    debugger;
    window.location.href = window.location.href.split("?")[0];
}