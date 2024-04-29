from rest_framework import filters


class CustomHighlightFilterBackend(filters.BaseFilterBackend):
    def filter_queryset(self, request, queryset, view):
        active = request.query_params.get('active', None)

        if active is not None:
            if active.lower() == 'true':
                queryset = queryset.filter(active=True)
            elif active.lower() == 'false':
                queryset = queryset.filter(active=False)
        return queryset
