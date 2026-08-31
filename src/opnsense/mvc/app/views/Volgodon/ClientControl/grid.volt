{# Module-owned grid partial compatible with both jquery.bootgrid and Tabulator-backed UIBootgrid. #}
<table id="{{ table_id }}" class="table table-condensed table-hover table-striped table-responsive" data-editDialog="{{ edit_dialog_id }}">
    <thead>
        <tr>
            {% for field in fields %}
            <th {% for key, value in field %} data-{{ key }}="{{ value }}"{% endfor %}>{{ field['label'] }}</th>
            {% endfor %}
            <th data-column-id="commands" data-width="{{ command_width|default('100') }}" data-formatter="commands" data-sortable="false">
                {{ lang._('Commands') }}
            </th>
        </tr>
    </thead>
    <tbody></tbody>
    <tfoot>
        <tr>
            <td></td>
            <td>
                {% if hide_add is not defined %}
                    <button data-action="add" type="button" class="btn btn-xs btn-primary" title="{{ lang._('Add') }}">
                        <span class="fa fa-plus fa-fw"></span>
                    </button>
                {% endif %}
                {% if hide_delete is not defined %}
                    <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default" title="{{ lang._('Delete selected') }}">
                        <span class="fa fa-trash-o fa-fw"></span>
                    </button>
                {% endif %}
                {% for id, command in grid_commands|default({}) %}
                    <button id="{{ id }}" type="button" class="{{ command['class']|default('') }}" title="{{ command['title']|default('') }}"
                        {% for key, data in command['data']|default({}) %}
                        data-{{ key }}="{{ data }}"
                        {% endfor %}>
                        <span class="{{ command['icon_class']|default('') }}"></span>
                    </button>
                {% endfor %}
            </td>
        </tr>
    </tfoot>
</table>
