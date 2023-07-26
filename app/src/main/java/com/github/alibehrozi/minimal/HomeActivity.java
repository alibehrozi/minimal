package com.github.alibehrozi.minimal;

import android.app.Activity;
import android.os.Bundle;
import android.widget.FrameLayout;

public class HomeActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        FrameLayout frame = new FrameLayout(this);
        FrameLayout.LayoutParams frameParams = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
        );
        frame.setLayoutParams(frameParams);
        setContentView(frame);
    }

    @Override
    public void onBackPressed() {
        moveTaskToBack(true);
    }
}