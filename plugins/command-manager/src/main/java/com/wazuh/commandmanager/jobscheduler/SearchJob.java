package com.wazuh.commandmanager.jobscheduler;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClientDemo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.*;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.search.Scroll;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.PointInTimeBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.threadpool.ThreadPool;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public class SearchJob {
    private static final Logger log = LogManager.getLogger(SearchJob.class);
    private static SearchJob INSTANCE;
    private ThreadPool threadPool;
    private Client client;
    private String scrollId;
    private String pitId;
    private Object[] searchAfter;
    private SearchResponse searchResponse;
    private SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();



    public void setPitId(String pitId) {
        this.pitId = pitId;
    }

    public String getPitId() {
        return pitId;
    }


    public static SearchJob getSearchJobInstance() {
        log.info("Getting Job Runner Instance");
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (SearchJob.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new SearchJob();
            return INSTANCE;
        }
    }

    public CompletableFuture<SearchResponse> search(String index, Integer resultsPerPage) {
        SearchRequest searchRequest = new SearchRequest(index);
        TermQueryBuilder termQueryBuilder = QueryBuilders.termQuery("command.status.keyword","PENDING");
        getSearchSourceBuilder().query(termQueryBuilder)
            .size(resultsPerPage);
        searchRequest.source(getSearchSourceBuilder());

        CompletableFuture<SearchResponse> completableFuture = new CompletableFuture<>();
        ExecutorService executorService = this.threadPool.executor(ThreadPool.Names.SEARCH);
        executorService.submit(
            () -> {
                try {
                    SearchResponse searchResponse = client.search(searchRequest).actionGet();
                    completableFuture.complete(searchResponse);
                } catch (Exception e) {
                    completableFuture.completeExceptionally(e);
                }
            }
        );
        return completableFuture;
    }

    private CompletableFuture<SearchResponse> scrollSearch(SearchScrollRequest searchScrollRequest) {
        CompletableFuture<SearchResponse> completableFuture = new CompletableFuture<>();
        ExecutorService executorService = this.threadPool.executor(ThreadPool.Names.SEARCH);
        executorService.submit(
            () -> {
                try {
                    SearchResponse searchResponse = client.searchScroll(searchScrollRequest).actionGet();
                    completableFuture.complete(searchResponse);
                } catch (Exception e) {
                    completableFuture.completeExceptionally(e);
                }
            }
        );
        return completableFuture;
    }

    Map<String, Object> checkAndTransform(Map<String, Object> inputMap) throws ClassCastException {
        Map<String, Object> result = new HashMap<>();
        for ( Map.Entry<String, Object> entry : inputMap.entrySet() ) {
            try {
                result.put(entry.getKey(), entry.getValue());
            } catch (ClassCastException e) {
                logStackTrace(e);
            }
        }
        return result;
    }

    @SuppressWarnings("Unchecked")
    public static <T> T getNestedValue(Map<String, Object> map, String key, Class<T> type) {
        Object value = map.get(key);
        if (type.isInstance(value)) {
            return type.cast(value);
        } else {
            throw new ClassCastException("Expected " + type + " but found " + (value != null ? value.getClass() : "null"));
        }
    }

    public void handleSearchResponse(SearchResponse searchResponse) throws Exception {
        SearchHits searchHits = searchResponse.getHits();
        for (SearchHit hit: searchHits) {
            Map<String,Object> commandMap = getNestedValue(hit.getSourceAsMap(), "command", Map.class);
            commandMap.put("status", "DONE");
            hit.getSourceAsMap().put("command", commandMap);
            IndexRequest indexRequest = new IndexRequest()
                .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                .source(hit.getSourceAsMap())
                .id(hit.getId());
            client.index(
                indexRequest,
                new ActionListener<IndexResponse>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                       log.debug("Updated command with document id: {}", hit.getId());
                    }
                    @Override
                    public void onFailure(Exception e) {
                        logStackTrace(e);
                    }
                }
            );
            XContentBuilder xContentBuilder = XContentFactory.jsonBuilder();
            hit.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);
            String uri = "https://httpbin.org/post";
            HttpRestClientDemo.run(uri, xContentBuilder.toString());
        }
    }

    public void pointInTimeSearch(String index, Integer resultsPerPage) {
        CreatePitRequest createPitRequest = new CreatePitRequest(TimeValue.timeValueMinutes(1L), false, index);
        client.createPit(createPitRequest, new ActionListener<>() {
            @Override
            public void onResponse(CreatePitResponse createPitResponse) {
                setPitId(createPitResponse.getId());
            }
            @Override
            public void onFailure(Exception e) {
                logStackTrace(e);
            }
        });
        SearchRequest searchRequest = new SearchRequest(index);
        final PointInTimeBuilder pointInTimeBuilder = new PointInTimeBuilder(getPitId());
        pointInTimeBuilder.setKeepAlive(TimeValue.timeValueMinutes(1L));
        TermQueryBuilder termQueryBuilder = QueryBuilders.termQuery("command.status.keyword","PENDING");
        getSearchSourceBuilder().query(termQueryBuilder)
            .size(resultsPerPage)
            .sort(Command.COMMAND + "." + Command.ORDER_ID, SortOrder.ASC)
            .sort(Command.COMMAND + "." + Command.TIMEOUT, SortOrder.ASC)
            .pointInTimeBuilder(pointInTimeBuilder);
        searchRequest.source(getSearchSourceBuilder());
        client.search(searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                try {
                    setSearchResponse(searchResponse);
                    handleSearchResponse(searchResponse);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            @Override
            public void onFailure(Exception e) {
                logStackTrace(e);
            }
        });

        SearchHit[] searchHits = getSearchResponse().getHits().getHits();
        if (searchHits != null && searchHits.length > 0) {
            searchAfter = searchHits[searchHits.length - 1].getSortValues();
            getSearchSourceBuilder().searchAfter(searchAfter);
        }
    }

    public void scrollSearchJob(String index, Integer resultsPerPage) {
        final Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));
        SearchRequest searchRequest = new SearchRequest(index);
        searchRequest.scroll(scroll);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        TermQueryBuilder termQueryBuilder = QueryBuilders.termQuery("command.status.keyword","PENDING");
        searchSourceBuilder.query(termQueryBuilder)
            .size(resultsPerPage)
            .sort(Command.COMMAND + "." + Command.TIMEOUT, SortOrder.ASC);
        searchRequest.source(searchSourceBuilder);
        client.search(searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                log.info("First search iteration completed successfully");
                try {
                    handleSearchResponse(searchResponse);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                setScrollId(searchResponse);
                setSearchResponse(searchResponse);
            }

            @Override
            public void onFailure(Exception e) {
                logStackTrace(e);
            }
        });

        SearchHit[] searchHits = searchResponse.getHits().getHits();

        while ( searchHits != null && searchHits.length > 0 ) {
            SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId);
            scrollRequest.scroll(scroll);
            client.searchScroll(scrollRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse searchResponse) {
                    log.info("Get next page of results");
                    try {
                        handleSearchResponse(searchResponse);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    setScrollId(searchResponse);
                    setSearchResponse(searchResponse);
                }
                @Override
                public void onFailure(Exception e) {
                    logStackTrace(e);
                }
            });
            searchHits = searchResponse.getHits().getHits();
        }

        ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
        clearScrollRequest.addScrollId(scrollId);
        client.clearScroll(clearScrollRequest, new ActionListener<>() {
            @Override
            public void onResponse(ClearScrollResponse clearScrollResponse) {
                log.info("Scroll successfully cleaned");
            }

            @Override
            public void onFailure(Exception e) {
                logStackTrace(e);
            }
        });
    }

    public void pointInTimeSearchJob(String index, Integer resultsPerPage) {

    }

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    private void setScrollId(SearchResponse searchResponse) {
        this.scrollId = searchResponse.getScrollId();
    }

    public SearchSourceBuilder getSearchSourceBuilder() {
        return searchSourceBuilder;
    }

    public void setSearchSourceBuilder(SearchSourceBuilder searchSourceBuilder) {
        this.searchSourceBuilder = searchSourceBuilder;
    }

    public void setSearchResponse(SearchResponse searchResponse) {
        this.searchResponse = searchResponse;
    }

    public SearchResponse getSearchResponse() {
        return searchResponse;
    }

    private static void logStackTrace(Throwable e) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(byteArrayOutputStream);
        e.printStackTrace(ps);
        log.error(byteArrayOutputStream.toString());
    }
}
