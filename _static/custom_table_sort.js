// Custom sorting and copy-to-clipboard for MUD server tables
$(document).ready(function() {
    setTimeout(function() {
        $('table.sphinx-datatable').each(function() {
            if ($.fn.DataTable.isDataTable(this)) {
                var table = $(this).DataTable();
                var headers = [];

                $(this).find('thead th').each(function() {
                    headers.push($(this).text().trim());
                });

                // Server list: sort by Players (descending)
                if (headers.includes('Players') && headers.includes('Name')) {
                    var playersIdx = headers.indexOf('Players');
                    table.order([playersIdx, 'desc']).draw();
                }
                // Fingerprint table: sort by Servers count (descending)
                else if (headers.includes('Fingerprint') && headers.includes('Servers')) {
                    var serversIdx = headers.indexOf('Servers');
                    table.order([serversIdx, 'desc']).draw();
                }
            }
        });

        // Add copy buttons to telnet links in tables
        $('table a[href^="telnet://"]').each(function() {
            var $link = $(this);
            if ($link.next('.copy-btn').length) return;
            var href = $link.attr('href');
            var match = href.match(/^telnet:\/\/([^:\/]+)(?::(\d+))?/);
            if (!match) return;
            var host = match[1];
            var port = match[2] || '23';
            var $btn = $('<button>')
                .addClass('copy-btn')
                .attr('data-host', host)
                .attr('data-port', port)
                .attr('title', 'Copy host and port')
                .attr('aria-label', 'Copy ' + host + ' port ' + port + ' to clipboard')
                .html('<span class="copy-icon" aria-hidden="true">&#x1F4CB;</span>');
            $link.after($btn);
        });

        // Add copy buttons to Show JSON / Show Logfile details elements
        $('details > summary').each(function() {
            var $summary = $(this);
            var label = $summary.text().trim();
            if (label !== 'Show JSON' && label !== 'Show Logfile') return;
            if ($summary.find('.copy-btn').length) return;
            var $btn = $('<button>')
                .addClass('copy-btn copy-block-btn')
                .attr('title', 'Copy to clipboard')
                .attr('aria-label', 'Copy ' + label.toLowerCase().replace('show ', '')
                    + ' to clipboard')
                .html('<span class="copy-icon" aria-hidden="true">&#x1F4CB;</span>');
            $summary.append($btn);
        });
    }, 200);

    // Copy button click handler (delegated for dynamic content)
    $(document).on('click', '.copy-btn', function(e) {
        e.preventDefault();
        e.stopPropagation();
        var $btn = $(this);
        var text;

        if ($btn.hasClass('copy-block-btn')) {
            // Copy code block content from parent <details>
            var $details = $btn.closest('details');
            var $code = $details.find('pre');
            text = $code.map(function() { return $(this).text(); }).get().join('\n');
        } else {
            // Copy host:port for telnet links
            var host = $btn.data('host');
            var port = $btn.data('port');
            text = host + ' ' + port;
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function() {
                $btn.find('.copy-icon').html('&#x2713;');
                setTimeout(function() {
                    $btn.find('.copy-icon').html('&#x1F4CB;');
                }, 1500);
            });
        } else {
            // Fallback for older browsers
            var $temp = $('<textarea>');
            $('body').append($temp);
            $temp.val(text).select();
            document.execCommand('copy');
            $temp.remove();
            $btn.find('.copy-icon').html('&#x2713;');
            setTimeout(function() {
                $btn.find('.copy-icon').html('&#x1F4CB;');
            }, 1500);
        }
    });
});
